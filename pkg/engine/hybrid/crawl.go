package hybrid

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"image/jpeg"
	"io"
	"mime"
	"net/http"
	"net/http/httputil"
	"net/url"
	"slices"
	"strings"
	"time"

	"github.com/PuerkitoBio/goquery"
	"github.com/go-rod/rod"
	"github.com/go-rod/rod/lib/proto"
	"github.com/projectdiscovery/gologger"
	"github.com/projectdiscovery/katana/pkg/engine/common"
	"github.com/projectdiscovery/katana/pkg/navigation"
	"github.com/projectdiscovery/katana/pkg/utils"
	"github.com/projectdiscovery/retryablehttp-go"
	"github.com/projectdiscovery/utils/errkit"
	mapsutil "github.com/projectdiscovery/utils/maps"
	sliceutil "github.com/projectdiscovery/utils/slice"
	stringsutil "github.com/projectdiscovery/utils/strings"
	urlutil "github.com/projectdiscovery/utils/url"
)

func (c *Crawler) navigateRequest(s *common.CrawlSession, request *navigation.Request) (*navigation.Response, error) {
	depth := request.Depth + 1
	response := &navigation.Response{
		Depth:        depth,
		RootHostname: s.Hostname,
	}

	page, err := s.Browser.Context(s.Ctx).Page(proto.TargetCreateTarget{})
	if err != nil {
		return nil, errkit.Wrap(err, "hybrid: could not create target")
	}
	// Keep the original page reference for cleanup — page.Context() returns a clone,
	// so closing only the clone after timeout would leak the original tab.
	cleanupPage := page
	// sessionPage is bound to the crawl session context so that DOM/HTML
	// operations with fresh timeouts still respect external cancellation.
	sessionPage := page.Context(s.Ctx)
	timeout := time.Duration(c.Options.Options.Timeout) * time.Second
	timeoutCtx, timeoutCancel := context.WithTimeout(s.Ctx, timeout)
	defer timeoutCancel()
	page = sessionPage.Context(timeoutCtx)

	defer func() {
		if err := cleanupPage.Close(); err != nil {
			gologger.Error().Msgf("Error closing page: %v\n", err)
		}
	}()
	c.addHeadersToPage(page)

	pageRouter := NewHijack(page)
	pageRouter.SetPattern(&proto.FetchRequestPattern{
		URLPattern:   "*",
		RequestStage: proto.FetchRequestStageResponse,
	})

	xhrRequests := []navigation.Request{}
	go pageRouter.Start(func(e *proto.FetchRequestPaused) error {
		URL, err := urlutil.Parse(e.Request.URL)
		if err != nil {
			return errkit.Wrap(err, "hybrid: could not parse URL")
		}
		body, _ := FetchGetResponseBody(page, e)

		headers := make(map[string][]string)
		for _, h := range e.ResponseHeaders {
			headers[h.Name] = []string{h.Value}
		}
		var (
			statusCode     int
			statucCodeText string
		)
		if e.ResponseStatusCode != nil {
			statusCode = *e.ResponseStatusCode
		}
		if e.ResponseStatusText != "" {
			statucCodeText = e.ResponseStatusText
		} else {
			statucCodeText = http.StatusText(statusCode)
		}
		httpreq, err := http.NewRequest(e.Request.Method, URL.String(), strings.NewReader(e.Request.PostData))
		if err != nil {
			return errkit.Wrap(err, "hybrid: could not new request")
		}
		// Note: headers are originally sent using `c.addHeadersToPage` below changes are done so that
		// headers are reflected in request dump
		// Headers, CustomHeaders, and Cookies are present in e.Request.Headers. We need to consider all of them and not only CustomHeaders
		// Otherwise, we will miss headers and output will be inconsistent
		if httpreq != nil {
			for k, v := range e.Request.Headers {
				httpreq.Header.Set(k, v.String())
			}
		}

		httpresp := &http.Response{
			Proto:         "HTTP/1.1",
			ProtoMajor:    1,
			ProtoMinor:    1,
			StatusCode:    statusCode,
			Status:        statucCodeText,
			Header:        headers,
			Body:          io.NopCloser(bytes.NewReader(body)),
			Request:       httpreq,
			ContentLength: int64(len(body)),
		}

		var rawBytesRequest, rawBytesResponse []byte
		if r, err := retryablehttp.FromRequest(httpreq); err == nil {
			rawBytesRequest, _ = r.Dump()
		} else {
			rawBytesRequest, _ = httputil.DumpRequestOut(httpreq, true)
		}
		rawBytesResponse, _ = httputil.DumpResponse(httpresp, true)

		bodyReader, _ := goquery.NewDocumentFromReader(bytes.NewReader(body))
		var technologies map[string]interface{}
		if c.Options.Wappalyzer != nil {
			fingerprints := c.Options.Wappalyzer.Fingerprint(headers, body)
			technologies = make(map[string]interface{}, len(fingerprints))
			for k := range fingerprints {
				technologies[k] = struct{}{}
			}
		}
		resp := &navigation.Response{
			Resp:          httpresp,
			Body:          string(body),
			Reader:        bodyReader,
			Depth:         depth,
			RootHostname:  s.Hostname,
			Technologies:  mapsutil.GetKeys(technologies),
			StatusCode:    statusCode,
			Headers:       utils.FlattenHeaders(headers),
			Raw:           string(rawBytesResponse),
			ContentLength: httpresp.ContentLength,
			KnowledgeBase: c.Options.BuildKnowledgeBase(string(body), httpreq, httpresp),
		}
		response.ContentLength = resp.ContentLength

		requestHeaders := make(map[string][]string)
		for name, value := range e.Request.Headers {
			requestHeaders[name] = []string{value.Str()}
		}

		shouldCapture := func(xhrExtraction bool) bool {
			resourceTypes := []proto.NetworkResourceType{
				proto.NetworkResourceTypeXHR,
				proto.NetworkResourceTypeFetch,
				proto.NetworkResourceTypeScript,
			}

			return xhrExtraction && slices.Contains(resourceTypes, e.ResourceType)
		}

		if shouldCapture(c.Options.Options.XhrExtraction) {
			networkReq := navigation.Request{
				URL:    httpreq.URL.String(),
				Method: httpreq.Method,
				Body:   e.Request.PostData,
			}
			if len(httpreq.Header) > 0 {
				networkReq.Headers = utils.FlattenHeaders(httpreq.Header)
			} else {
				networkReq.Headers = utils.FlattenHeaders(requestHeaders)
			}
			xhrRequests = append(xhrRequests, networkReq)
		}

		// trim trailing /
		normalizedheadlessURL := strings.TrimSuffix(e.Request.URL, "/")
		matchOriginalURL := stringsutil.EqualFoldAny(request.URL, e.Request.URL, normalizedheadlessURL)

		// Content uniqueness / page-similarity gates apply only to the main
		// document. Rejected main docs still record response metadata so the
		// crawl does not end with "hybrid: response is nil"; only parse/enqueue
		// is suppressed. Scripts and XHR keep flowing for extraction.
		skipParse := false
		if matchOriginalURL {
			if !c.Options.Options.DisableUniqueFilter && !c.Options.UniqueFilter.UniqueContent(body) {
				skipParse = true
			}
			if !skipParse && c.Options.ContentSimilarity != nil && !c.Options.ContentSimilarity.Accept(body) {
				skipParse = true
			}
			request.Raw = string(rawBytesRequest)
			response = resp
		}

		if !skipParse {
			navigationRequests := c.Options.Parser.ParseResponse(resp)
			c.Enqueue(s.Queue, navigationRequests...)
		}

		// do not continue following the request if it's a redirect and redirects are disabled
		if c.Options.Options.DisableRedirects && resp.IsRedirect() {
			return nil
		}
		return FetchContinueRequest(page, e)
	})() //nolint
	defer func() {
		if err := pageRouter.Stop(); err != nil {
			gologger.Warning().Msgf("%s\n", err)
		}
	}()

	navigatedURLs := sliceutil.NewSyncSlice[string]()
	navigatedURLs.Append(request.URL)

	pageCtx, cancelPageEvents := page.WithCancel()
	defer cancelPageEvents()

	waitFrameEvents := pageCtx.EachEvent(func(e *proto.PageFrameNavigated) {
		if e.Frame.ParentID == "" {
			frameURL := e.Frame.URL
			if frameURL != "" && frameURL != request.URL {
				navigatedURLs.Append(frameURL)
			}
		}
	})
	go waitFrameEvents()

	// Arm the lifecycle listener before navigate so the event is not missed.
	// Which event we wait for depends on the page-load strategy.
	strategy := c.Options.Options.PageLoadStrategy

	var waitNavigation func()
	switch strategy {
	case "none":
		// no lifecycle wait
	case "domcontentloaded":
		waitNavigation = page.WaitNavigation(proto.PageLifecycleEventNameDOMContentLoaded)
	case "load":
		waitNavigation = page.WaitNavigation(proto.PageLifecycleEventNameLoad)
	default:
		waitNavigation = page.WaitNavigation(proto.PageLifecycleEventNameFirstMeaningfulPaint)
	}

	err = page.Navigate(request.URL)
	if err != nil {
		if c.Options.Options.DisableRedirects && response.IsRedirect() {
			return response, nil
		}
		return nil, errkit.Wrap(err, "hybrid: could not navigate target")
	}

	if waitNavigation != nil {
		waitNavigation()
	}

	// Post-navigation stability wait, strategy-specific
	switch strategy {
	case "none":
		gologger.Debug().Msgf("page-load-strategy=none: skipping stability wait\n")

	case "domcontentloaded":
		waitTime := time.Duration(c.Options.Options.DOMWaitTime) * time.Second
		gologger.Debug().Msgf("page-load-strategy=domcontentloaded: waiting %s for DOM\n", waitTime)
		if waitTime > 0 {
			time.Sleep(waitTime)
		}

	case "load":
		gologger.Debug().Msgf("page-load-strategy=load: basic load wait only\n")
		time.Sleep(500 * time.Millisecond)

	default:
		timeStable := time.Duration(c.Options.Options.TimeStable) * time.Second

		if timeout < timeStable {
			gologger.Warning().Msgf("timeout is less than time stable, setting time stable to half of timeout to avoid timeout\n")
			timeStable = timeout / 2
			gologger.Warning().Msgf("setting time stable to %s\n", timeStable)
		}

		if timeStable > 0 {
			if err := page.WaitStable(timeStable); err != nil {
				gologger.Warning().Msgf("could not wait for page to be stable: %s\n", err)
			}
		} else {
			gologger.Debug().Msgf("time-stable is non-positive: skipping stability wait\n")
		}
	}

	// simulate clicks on links with onclick handlers to discover JS redirects
	select {
	case <-timeoutCtx.Done():
		return nil, timeoutCtx.Err()
	case <-time.After(200 * time.Millisecond):
	}

	maxLinks := c.Options.Options.MaxOnclickLinks
	clickableLinks, err := page.Elements("a[onclick]")
	if maxLinks > 0 && err == nil && len(clickableLinks) > 0 {
		linksToProcess := len(clickableLinks)
		if linksToProcess > maxLinks {
			linksToProcess = maxLinks
		}

		gologger.Debug().Msgf("Found %d clickable links with onclick handlers, processing %d", len(clickableLinks), linksToProcess)

		for idx := 0; idx < linksToProcess; idx++ {
			link := clickableLinks[idx]
			beforeURL, err := page.Info()
			if err != nil {
				gologger.Error().Msgf("Could not get page info: %v", err)
				continue
			}
			beforeURLStr := ""
			if beforeURL != nil {
				beforeURLStr = beforeURL.URL
			}

			// try to click the link using rod's Click method
			clickErr := link.Click(proto.InputMouseButtonLeft, 1)
			if clickErr != nil {
				gologger.Debug().Msgf("Could not click link %d: %v", idx, clickErr)
				continue
			}

			gologger.Debug().Msgf("Clicked onclick link [%d] at URL: %s", idx, beforeURLStr)

			select {
			case <-timeoutCtx.Done():
				return nil, timeoutCtx.Err()
			case <-time.After(1 * time.Second):
			}

			// check if URL changed (indicates redirect occurred)
			currentURL, _ := page.Info()
			if currentURL != nil && currentURL.URL != beforeURLStr {
				gologger.Debug().Msgf("detected navigation to: %s", currentURL.URL)
				navigatedURLs.Append(currentURL.URL)

				if navErr := page.Navigate(request.URL); navErr != nil {
					gologger.Warning().Msgf("Failed to navigate back to %s after onclick redirect: %v", request.URL, navErr)
					if reloadErr := page.Reload(); reloadErr != nil {
						gologger.Error().Msgf("Failed to reload page after navigation error: %v", reloadErr)
						break
					}
				}
				select {
				case <-timeoutCtx.Done():
					return nil, timeoutCtx.Err()
				case <-time.After(500 * time.Millisecond):
				}
			}
		}
	}

	// Attempt to get the full DOM tree for shadow DOM traversal.
	// Use basePage (pre-timeout) with a fresh timeout so that DOM inspection
	// does not share the navigation timeout budget. If it fails (e.g. timeout
	// on complex SPAs), we still proceed with regular page HTML.
	var domResult *proto.DOMGetDocumentResult
	domPage := sessionPage.Timeout(timeout)
	var getDocumentDepth = int(-1)
	getDocument := &proto.DOMGetDocument{Depth: &getDocumentDepth, Pierce: true}
	domResult, domErr := getDocument.Call(domPage)
	if domErr != nil {
		gologger.Warning().Msgf("could not get dom for %s: %s (continuing with page HTML)", request.URL, domErr)
	}

	// Use basePage with a fresh timeout for HTML retrieval so it succeeds
	// even if the navigation or DOM timeout was exhausted.
	body, err := sessionPage.Timeout(timeout).HTML()
	if err != nil {
		return nil, errkit.Wrap(err, "hybrid: could not get html")
	}

	parsed, err := urlutil.Parse(request.URL)
	if err != nil {
		return nil, errkit.Wrap(err, "hybrid: url could not be parsed")
	}

	if response == nil || response.Resp == nil {
		// err is guaranteed to be nil, due to previous checks.
		return nil, errors.New("hybrid: response is nil")
	}
	response.Resp.Request.URL = parsed.URL

	// Create a copy of interpolated shadow DOM elements and parse them separately
	if domResult != nil && domResult.Root != nil {
		var builder strings.Builder
		traverseDOMNode(domResult.Root, &builder)

		responseCopy := *response
		responseCopy.Body = builder.String()

		responseCopy.Reader, _ = goquery.NewDocumentFromReader(strings.NewReader(responseCopy.Body))
		if responseCopy.Reader != nil {
			navigationRequests := c.Options.Parser.ParseResponse(&responseCopy)
			c.Enqueue(s.Queue, navigationRequests...)
		}
	}

	response.Body = body
	if response.Reader != nil {
		response.Reader.Url, _ = url.Parse(request.URL)
		if c.Options.Options.FormExtraction {
			response.Forms = append(response.Forms, utils.ParseFormFields(response.Reader)...)
		}
	}

	response.Reader, err = goquery.NewDocumentFromReader(strings.NewReader(response.Body))
	if err != nil {
		return nil, errkit.Wrap(err, "hybrid: could not parse html")
	}

	// FORK PATCH 12: evaluate the caller-supplied version-probe script now
	// that the page has fully rendered (HTML captured above), and attach
	// the result ONLY to this rendered-page response -- never to the
	// sub-resource (.js/.css/xhr) responses built inside the hijack
	// callback above.
	response.Versions = c.evaluateVersionProbe(sessionPage)

	// FORK PATCH 13: capture one above-the-fold viewport screenshot, at the
	// same seam and for the same reason as patch 12 above -- the page has
	// fully rendered here, and this is the rendered-page response, never a
	// sub-resource (.js/.css/xhr) response built inside the hijack callback.
	//
	// The seam alone is NOT enough to identify the home page. The parser
	// turns every script[src] into its own navigation request (and
	// -jsluice/-scrape-js adds more), those are enqueued from inside the
	// hijack callback WHILE THE SEED IS STILL LOADING, and a .js URL opened
	// as its own page renders as plain text and reaches this line long
	// before the seed does. The gate inside is what keeps the slot for the
	// seed's own HTML document.
	if screenshot := c.captureViewportScreenshot(timeoutCtx, sessionPage, request, response.Resp); screenshot != nil {
		response.Screenshot = screenshot
		response.ScreenshotFormat = "jpeg"
	}

	response.XhrRequests = xhrRequests

	// enqueue JS-triggered navigation URLs that were detected
	navigatedURLs.Each(func(i int, navURL string) error {
		if navURL != request.URL {
			parsed, err := urlutil.Parse(navURL)
			if err == nil {
				navReq := &navigation.Request{
					URL:          parsed.String(),
					Depth:        depth,
					RootHostname: s.Hostname,
				}
				c.Enqueue(s.Queue, navReq)
				gologger.Debug().Msgf("enqueued JS navigation: %s", navURL)
			}
		}
		return nil
	})

	return response, nil
}

func (c *Crawler) addHeadersToPage(page *rod.Page) {
	// FORK PATCH 11: seeding (below) must run even when there are no custom
	// headers, so the empty-Headers early return this function used to open
	// with is now scoped to the header loop only. Do NOT reinstate a top-level
	// `if len(c.Headers) == 0 { return }` -- it silently disables cookie and
	// JS-storage seeding on every crawl that sets no custom header.
	if len(c.Headers) > 0 {
		var arr []string

		for k, v := range c.Headers {
			switch {
			case stringsutil.EqualFoldAny(k, "User-Agent"):
				userAgentParams := &proto.NetworkSetUserAgentOverride{
					UserAgent: v,
				}
				if err := page.SetUserAgent(userAgentParams); err != nil {
					gologger.Error().Msgf("headless: could not set user agent: %v", err)
				}
			default:
				arr = append(arr, k, v)
			}
		}

		if len(arr) > 0 {
			_, err := page.SetExtraHeaders(arr)
			if err != nil {
				gologger.Error().Msgf("headless: could not set extra headers: %v", err)
			}
		}
	}

	// FORK PATCH 11: seed per-scan session material before navigation.
	//
	// Cookies are domain-scoped by SetCookies, so the browser enforces scope.
	// This is the AUTHORITATIVE cookie injection for the hybrid path; the
	// proxy (patch 8) only merges distinct extras and never overwrites these.
	if len(c.Options.Options.SeedCookies) > 0 {
		if err := page.SetCookies(c.Options.Options.SeedCookies); err != nil {
			gologger.Error().Msgf("headless: could not set seed cookies: %v", err)
		}
	}
	// JS-storage: EvalOnNewDocument (addScriptToEvaluateOnNewDocument) runs in
	// EVERY new document, INCLUDING third-party iframes. An unguarded
	// localStorage.setItem(token) would leak the session to third-party
	// origins. The injected script MUST self-gate on location.origin against
	// the in-scope allowlist -- CDP cannot target the injection by origin, so
	// the gate lives in the script itself (built on the nikto-platform side).
	if len(c.Options.Options.SeedStorageScript) > 0 {
		if _, err := page.EvalOnNewDocument(c.Options.Options.SeedStorageScript); err != nil {
			gologger.Error().Msgf("headless: could not seed storage script: %v", err)
		}
	}
}

// FORK PATCH 12: post-render version-probe limits. maxProbeRawBytes bounds
// the raw string handed back over CDP BEFORE it is ever parsed -- the page
// fully controls its own output (a hostile/compromised page can return a
// gigabyte string regardless of any in-page .slice()), so this is the real
// control, enforced at the point the CDP payload is first seen in Go.
// maxProbeEntries/maxProbeValueBytes are a secondary belt-and-suspenders cap
// on the parsed map (the api side re-applies its own caps independently).
const (
	versionProbeTimeout = 3 * time.Second
	maxProbeRawBytes    = 16 * 1024
	maxProbeEntries     = 32
	maxProbeValueBytes  = 64
)

// evaluateVersionProbe runs c.Options.Options.VersionProbeScript against the
// live, already-rendered page and returns a component->version map, or nil
// on ANY failure (no script configured, eval throw, timeout, oversized
// result, invalid JSON). A probe failure must never fail the page crawl --
// the caller always continues with the rest of navigateRequest regardless
// of what this returns.
func (c *Crawler) evaluateVersionProbe(page *rod.Page) map[string]string {
	script := c.Options.Options.VersionProbeScript
	if script == "" {
		return nil
	}

	// Bounded context: this is the ONLY thing that catches a hanging getter
	// inside the probe (there is no per-statement timeout inside the JS
	// itself). Correctly discarding the whole page's versions when the
	// probe hangs is intended, never-fatal behavior.
	probePage := page.Timeout(versionProbeTimeout)

	// Wrap the caller's script so its result is always returned as a JSON
	// string via JSON.stringify, and so a thrown exception inside the
	// probe never propagates as a Go-visible eval error.
	wrapped := fmt.Sprintf(`() => {
		try {
			return JSON.stringify((function() { %s })());
		} catch (e) {
			return "";
		}
	}`, script)

	obj, err := probePage.Eval(wrapped)
	if err != nil {
		gologger.Debug().Msgf("hybrid: version probe eval failed (never fatal): %v", err)
		return nil
	}

	raw := obj.Value.Str()
	if raw == "" {
		return nil
	}
	// Bound the raw bytes BEFORE parsing -- this is where the CDP payload
	// is first seen in Go.
	if len(raw) > maxProbeRawBytes {
		gologger.Debug().Msgf("hybrid: version probe result exceeded %d bytes, discarding", maxProbeRawBytes)
		return nil
	}

	var parsed map[string]string
	if err := json.Unmarshal([]byte(raw), &parsed); err != nil {
		gologger.Debug().Msgf("hybrid: version probe result was not a JSON object of strings: %v", err)
		return nil
	}
	if len(parsed) == 0 {
		return nil
	}

	capped := make(map[string]string, min(len(parsed), maxProbeEntries))
	count := 0
	for k, v := range parsed {
		if count >= maxProbeEntries {
			break
		}
		if len(v) > maxProbeValueBytes {
			v = v[:maxProbeValueBytes]
		}
		capped[k] = v
		count++
	}
	return capped
}

// FORK PATCH 13: viewport-screenshot limits.
//
// Every duration here is spent INSIDE the seed page's per-navigation timeout
// (navigateRequest's timeoutCtx). An overrun does not merely lose the
// screenshot: it loses the seed's rendered response, and with it every
// JS-discovered link -- the same failure the page-load-strategy default
// exists to avoid. They are deliberately short for that reason. Lengthen only
// on evidence that the longer wait produces better captures.
const (
	screenshotTimeout = 3 * time.Second
	screenshotQuality = 70
	// screenshotLoadWait bounds the pre-shot wait for window.onload. Pages
	// that already fired it pay nothing.
	screenshotLoadWait = 2 * time.Second
	// A capture that comes back blank is re-taken: the common case is a
	// fetch-then-render SPA whose DOM is complete but whose viewport is still
	// empty at DOMContentLoaded + DOMWaitTime.
	screenshotRetries   = 2
	screenshotRetryWait = 1 * time.Second
	// screenshotBudget caps the whole block (wait + shots + retries), further
	// clamped to what is left of the navigation deadline.
	screenshotBudget = 6 * time.Second
	// screenshotMinBudget is the least remaining navigation budget worth
	// starting a capture with: below it we would spend the seed page's last
	// moments on a picture instead of on returning its rendered DOM.
	screenshotMinBudget = 1500 * time.Millisecond
	// screenshotMinBytes: a JPEG of a uniform viewport compresses to almost
	// nothing, so size is a cheap pre-filter before the decode-and-sample.
	screenshotMinBytes = 3 * 1024
	// screenshotBlankVariance is the sampled-luma variance below which a
	// capture counts as blank (0 = every sampled pixel identical). A spinner
	// on white sits well under it. A bot-check or block interstitial does
	// NOT -- those carry text, and photographing them is intended: what the
	// scanner was served is exactly what the operator needs to see.
	screenshotBlankVariance = 25.0
	// screenshotSampleStride subsamples the decoded image; a full per-pixel
	// pass over a viewport JPEG is pointless for a variance estimate.
	screenshotSampleStride = 16
)

// captureViewportScreenshot returns one above-the-fold JPEG of the live,
// already-rendered page, or nil on ANY failure (screenshots disabled, another
// page already claimed the single per-crawl slot, CDP error, timeout, no
// budget left).
//
// ONCE PER CRAWL SESSION, AND ONLY FOR THE SEED'S OWN HTML DOCUMENT.
// Capturing every page would push hundreds of image blobs into Postgres, so a
// crawl gets exactly one picture and it must be of the home page.
//
// Two gates decide that, both BEFORE the CompareAndSwap, so a rejected page
// never consumes the single slot:
//
//   - request.Depth == 0 -- the seed, and only the seed. "First page to reach
//     this line" is NOT the seed: script[src] URLs are enqueued from inside
//     the seed's own hijack callback while the seed is still rendering, and
//     several hybrid workers navigate them concurrently. A .js page has no
//     sub-resources and no render work, so it arrives here first and Chrome
//     photographs JavaScript source as plain text.
//   - the response's Content-Type is HTML. A seed that redirects to a file
//     download, or a host whose root serves JSON, is not worth a picture.
//
// NO FALLBACK IS INTENDED. If the seed cannot be photographed the target gets
// no screenshot at all: a picture of the wrong page is worse than none,
// because nothing downstream distinguishes it from a correct capture.
//
// The atomic CompareAndSwap still guards the slot for the case a seed is
// retried or a session somehow carries more than one depth-0 request.
//
// A screenshot failure must never fail the page crawl -- the caller always
// continues with the rest of navigateRequest regardless of what this returns.
// It is, however, never silent: every give-up path logs a warning naming the
// URL, because a page photographed before it finished rendering is otherwise
// indistinguishable from a correct capture.
func (c *Crawler) captureViewportScreenshot(ctx context.Context, page *rod.Page, request *navigation.Request, resp *http.Response) []byte {
	if !c.Options.Options.ScreenshotViewport {
		return nil
	}
	if request == nil {
		return nil
	}
	targetURL := request.URL
	// Seed only. Children are enqueued with Depth = parent + 1 (see the top of
	// navigateRequest), so depth 0 is the one URL the operator asked for.
	if request.Depth != 0 {
		return nil
	}
	// HTML only. Silent on a non-HTML seed would be indistinguishable from a
	// capture that simply failed, so it is logged.
	if !isHTMLResponse(resp) {
		gologger.Warning().Msgf("hybrid: no viewport screenshot of %s: seed is not HTML (content-type %q)", targetURL, responseContentType(resp))
		return nil
	}
	// Guard is claimed AFTER the cheap gates but BEFORE any wait or CDP call:
	// a failed/timed-out attempt still consumes the slot, so a hostile seed
	// cannot make every subsequent page pay for a screenshot attempt.
	if !c.screenshotTaken.CompareAndSwap(false, true) {
		return nil
	}

	budget := screenshotBudget
	if deadline, ok := ctx.Deadline(); ok {
		if remaining := time.Until(deadline); remaining < budget {
			budget = remaining
		}
	}
	if budget < screenshotMinBudget {
		gologger.Warning().Msgf("hybrid: skipped viewport screenshot of %s: only %s of the navigation budget left", targetURL, budget)
		return nil
	}
	deadline := time.Now().Add(budget)

	// window.onload, bounded. Returns immediately when already fired, which is
	// the usual case by the time navigateRequest reaches here. Deliberately
	// NOT WaitRequestIdle: katana's hijack holds every request paused until
	// its handler continues it, so request-idle is not reachable on an
	// ordinary page and would burn its full timeout on every crawl.
	if wait := timeLeft(deadline, screenshotLoadWait); wait > 0 {
		if err := page.Timeout(wait).WaitLoad(); err != nil {
			gologger.Debug().Msgf("hybrid: pre-screenshot load wait for %s ended early (never fatal): %v", targetURL, err)
		}
	}

	var best []byte
	for attempt := 0; attempt <= screenshotRetries; attempt++ {
		shot := c.screenshotOnce(page, deadline)
		if len(shot) > len(best) {
			best = shot
		}
		if len(shot) > 0 && !screenshotIsBlank(shot) {
			return shot
		}
		if attempt == screenshotRetries {
			break
		}
		pause := timeLeft(deadline, screenshotRetryWait)
		if pause <= 0 {
			gologger.Warning().Msgf("hybrid: viewport screenshot of %s still blank and out of budget after %d attempt(s)", targetURL, attempt+1)
			break
		}
		select {
		case <-ctx.Done():
			gologger.Warning().Msgf("hybrid: viewport screenshot of %s abandoned: navigation context ended after %d attempt(s)", targetURL, attempt+1)
			return best
		case <-time.After(pause):
		}
	}

	if len(best) == 0 {
		gologger.Warning().Msgf("hybrid: viewport screenshot of %s produced no image; none will be stored", targetURL)
		return nil
	}
	// A genuinely blank page is a real answer, so the last capture is still
	// returned -- but the operator is told the page may not have finished
	// rendering rather than left to trust the picture.
	gologger.Warning().Msgf("hybrid: viewport screenshot of %s still looks blank after %d attempt(s); storing it anyway -- the page may not have finished rendering", targetURL, screenshotRetries+1)
	return best
}

// responseContentType returns the response's raw Content-Type header, or ""
// when there is no response or no header.
func responseContentType(resp *http.Response) string {
	if resp == nil {
		return ""
	}
	return resp.Header.Get("Content-Type")
}

// isHTMLResponse reports whether the response is an HTML document, using only
// the declared media type -- never a sniff of the body, which is
// hostile-controlled. A missing Content-Type is NOT treated as HTML: "could
// not determine" is not permission to proceed as if the answer were yes.
func isHTMLResponse(resp *http.Response) bool {
	ct := responseContentType(resp)
	if ct == "" {
		return false
	}
	if mediaType, _, err := mime.ParseMediaType(ct); err == nil {
		ct = mediaType
	} else if idx := strings.IndexByte(ct, ';'); idx >= 0 {
		ct = ct[:idx]
	}
	ct = strings.ToLower(strings.TrimSpace(ct))
	return ct == "text/html" || ct == "application/xhtml+xml"
}

// timeLeft returns want, clamped to the time remaining before deadline.
func timeLeft(deadline time.Time, want time.Duration) time.Duration {
	if remaining := time.Until(deadline); remaining < want {
		return remaining
	}
	return want
}

// screenshotOnce takes a single capture, bounded by the smaller of
// screenshotTimeout and what is left of the caller's deadline. Returns nil on
// any error.
func (c *Crawler) screenshotOnce(page *rod.Page, deadline time.Time) []byte {
	timeout := timeLeft(deadline, screenshotTimeout)
	if timeout <= 0 {
		return nil
	}
	quality := screenshotQuality
	// fullPage=false is REQUIRED: we want only the visible viewport
	// ("above the fold"), never a stitched full-page capture (which would
	// resize the viewport and repaint the page mid-crawl).
	data, err := page.Timeout(timeout).Screenshot(false, &proto.PageCaptureScreenshot{
		Format:  proto.PageCaptureScreenshotFormatJpeg,
		Quality: &quality,
	})
	if err != nil {
		gologger.Debug().Msgf("hybrid: viewport screenshot attempt failed (never fatal): %v", err)
		return nil
	}
	if len(data) == 0 {
		return nil
	}
	return data
}

// screenshotIsBlank reports whether a capture is visually empty -- a uniform
// field of one colour, which is what a page still waiting on its first render
// photographs as.
//
// It is a HEURISTIC and only ever costs a retry, so it is tuned conservative:
// anything with text, images or browser chrome in it has luma variance far
// above the threshold and counts as a real capture. Undecodable bytes count as
// blank; there is nothing useful to store either way.
func screenshotIsBlank(data []byte) bool {
	if len(data) < screenshotMinBytes {
		return true
	}
	img, err := jpeg.Decode(bytes.NewReader(data))
	if err != nil {
		gologger.Debug().Msgf("hybrid: could not decode viewport screenshot for the blank check: %v", err)
		return true
	}
	b := img.Bounds()
	if b.Dx() == 0 || b.Dy() == 0 {
		return true
	}

	var n, sum, sumSq float64
	for y := b.Min.Y; y < b.Max.Y; y += screenshotSampleStride {
		for x := b.Min.X; x < b.Max.X; x += screenshotSampleStride {
			r, g, bl, _ := img.At(x, y).RGBA()
			// Rec. 601 luma, scaled back from the 16-bit values RGBA returns.
			luma := (0.299*float64(r) + 0.587*float64(g) + 0.114*float64(bl)) / 257
			n++
			sum += luma
			sumSq += luma * luma
		}
	}
	if n == 0 {
		return true
	}
	mean := sum / n
	return sumSq/n-mean*mean < screenshotBlankVariance
}

// traverseDOMNode performs traversal of node completely building a pseudo-HTML
// from it including the Shadow DOM, Pseudo elements and other children.
//
// TODO: Remove this method when we implement human-like browser navigation
// which will anyway use browser APIs to find elements instead of goquery
// where they will have shadow DOM information.
func traverseDOMNode(node *proto.DOMNode, builder *strings.Builder) {
	buildDOMFromNode(node, builder)
	if node.TemplateContent != nil {
		traverseDOMNode(node.TemplateContent, builder)
	}
	if node.ContentDocument != nil {
		traverseDOMNode(node.ContentDocument, builder)
	}
	for _, children := range node.Children {
		traverseDOMNode(children, builder)
	}
	for _, shadow := range node.ShadowRoots {
		traverseDOMNode(shadow, builder)
	}
	for _, pseudo := range node.PseudoElements {
		traverseDOMNode(pseudo, builder)
	}
}

const (
	elementNode = 1
)

var knownElements = map[string]struct{}{
	"a": {}, "applet": {}, "area": {}, "audio": {}, "base": {}, "blockquote": {}, "body": {}, "button": {}, "embed": {}, "form": {}, "frame": {}, "html": {}, "iframe": {}, "img": {}, "import": {}, "input": {}, "isindex": {}, "link": {}, "meta": {}, "object": {}, "script": {}, "svg": {}, "table": {}, "video": {},
}

func buildDOMFromNode(node *proto.DOMNode, builder *strings.Builder) {
	if node.NodeType != elementNode {
		return
	}
	if _, ok := knownElements[node.LocalName]; !ok {
		return
	}
	builder.WriteRune('<')
	builder.WriteString(node.LocalName)
	builder.WriteRune(' ')
	if len(node.Attributes) > 0 {
		for i := 0; i < len(node.Attributes); i = i + 2 {
			builder.WriteString(node.Attributes[i])
			builder.WriteRune('=')
			builder.WriteString("\"")
			builder.WriteString(node.Attributes[i+1])
			builder.WriteString("\"")
			builder.WriteRune(' ')
		}
	}
	builder.WriteRune('>')
	builder.WriteString("</")
	builder.WriteString(node.LocalName)
	builder.WriteRune('>')
}
