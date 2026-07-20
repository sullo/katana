package hybrid

import (
	"testing"

	"github.com/projectdiscovery/katana/pkg/types"
)

func TestNew_RejectsHeadlessNoIncognito(t *testing.T) {
	// Must reject BEFORE launching or connecting to anything, so this test
	// needs no Chrome. If it ever hangs or tries to dial, the guard has been
	// moved below the launcher and the rejection is no longer structural.
	opts := &types.CrawlerOptions{Options: &types.Options{HeadlessNoIncognito: true}}
	c, err := New(opts)
	if err == nil {
		t.Fatal("HeadlessNoIncognito must be rejected: it drops the proxy and makes Close kill a shared browser")
	}
	if c != nil {
		t.Error("no crawler may be returned on rejection")
	}
}
