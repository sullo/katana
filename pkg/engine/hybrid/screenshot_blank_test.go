package hybrid

import (
	"bytes"
	"image"
	"image/color"
	"image/jpeg"
	"math/rand"
	"testing"
	"time"
)

// FORK PATCH 13 regression: the blank check is what decides whether a capture
// is re-taken, so a false "not blank" silently ships the picture of a page
// that had not rendered yet -- exactly the bug the retry exists to fix.

func encodeJPEG(t *testing.T, img image.Image) []byte {
	t.Helper()
	var buf bytes.Buffer
	if err := jpeg.Encode(&buf, img, &jpeg.Options{Quality: screenshotQuality}); err != nil {
		t.Fatalf("encode: %v", err)
	}
	return buf.Bytes()
}

func uniformImage(c color.Color) image.Image {
	img := image.NewRGBA(image.Rect(0, 0, 1280, 720))
	for y := 0; y < 720; y++ {
		for x := 0; x < 1280; x++ {
			img.Set(x, y, c)
		}
	}
	return img
}

func TestScreenshotIsBlank(t *testing.T) {
	t.Run("uniform white is blank", func(t *testing.T) {
		if !screenshotIsBlank(encodeJPEG(t, uniformImage(color.White))) {
			t.Fatal("uniform white viewport should read as blank")
		}
	})

	t.Run("uniform dark is blank", func(t *testing.T) {
		if !screenshotIsBlank(encodeJPEG(t, uniformImage(color.RGBA{18, 18, 18, 255}))) {
			t.Fatal("uniform dark viewport should read as blank (dark-mode shell before render)")
		}
	})

	t.Run("rendered content is not blank", func(t *testing.T) {
		img := image.NewRGBA(image.Rect(0, 0, 1280, 720))
		for y := 0; y < 720; y++ {
			for x := 0; x < 1280; x++ {
				img.Set(x, y, color.White)
			}
		}
		// Dark bands standing in for text/chrome: sparse, but everywhere the
		// sampling grid looks.
		for y := 0; y < 720; y += 40 {
			for dy := 0; dy < 12 && y+dy < 720; dy++ {
				for x := 0; x < 1000; x++ {
					img.Set(x, y+dy, color.RGBA{20, 20, 20, 255})
				}
			}
		}
		if screenshotIsBlank(encodeJPEG(t, img)) {
			t.Fatal("page with content should not read as blank")
		}
	})

	t.Run("noise is not blank", func(t *testing.T) {
		rng := rand.New(rand.NewSource(1))
		img := image.NewRGBA(image.Rect(0, 0, 640, 480))
		for y := 0; y < 480; y++ {
			for x := 0; x < 640; x++ {
				v := uint8(rng.Intn(256))
				img.Set(x, y, color.RGBA{v, v, v, 255})
			}
		}
		if screenshotIsBlank(encodeJPEG(t, img)) {
			t.Fatal("noisy image should not read as blank")
		}
	})

	t.Run("tiny and undecodable payloads are blank", func(t *testing.T) {
		if !screenshotIsBlank(nil) {
			t.Fatal("nil should read as blank")
		}
		if !screenshotIsBlank(bytes.Repeat([]byte{0xff}, screenshotMinBytes+1)) {
			t.Fatal("undecodable bytes should read as blank")
		}
	})
}

func TestTimeLeftClampsToDeadline(t *testing.T) {
	if got := timeLeft(time.Now().Add(time.Hour), time.Second); got != time.Second {
		t.Fatalf("want full want-duration, got %s", got)
	}
	if got := timeLeft(time.Now().Add(100*time.Millisecond), time.Second); got > 100*time.Millisecond {
		t.Fatalf("want clamped to remaining, got %s", got)
	}
	if got := timeLeft(time.Now().Add(-time.Second), time.Second); got > 0 {
		t.Fatalf("want non-positive past the deadline, got %s", got)
	}
}
