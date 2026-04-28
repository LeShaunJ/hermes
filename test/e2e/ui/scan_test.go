//go:build e2e

package uie2e

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/chromedp/chromedp"

	"github.com/leshaunj/hermes/internal/db"
)

// TestScanCompletion_DetailViewUpdates exercises the SSE-driven detail
// refresh.  This is the regression test for the morph dispatch bug:
// when refreshElement called htmx.swap() without a contextElement, the
// morph extension never ran and the page stayed on "queued" + the
// "scanning…" spinner forever.  This test would have caught it — a
// real scan completion event arrives, the detail view must repaint,
// and the state cell must show "scanned" before the deadline.
func TestScanCompletion_DetailViewUpdates(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping browser-driven test in -short mode")
	}

	stack := newStack(t)
	stack.Insert(&db.Image{
		ID:          1,
		RegistryURL: "registry.example.com",
		Repository:  "myorg/myapp",
		TagName:     "v1",
		Digest:      "sha256:" + strings.Repeat("a", 64),
		Arch:        "amd64",
		OS:          "linux",
		State:       db.StateQueued,
	})

	// Gate the scan func so the test owns timing: block until close,
	// then deliver a tiny but valid report.  Once it returns, the mock
	// store transitions the image to `scanned` and fans the LogEvent
	// out over SSE — same shape the real listener delivers.
	trigger := make(chan struct{})
	scanned := make(chan struct{})
	stack.SetScanFunc(func(ref string) ([]byte, error) {
		<-trigger
		defer close(scanned)
		return []byte(`{"Results":[]}`), nil
	})

	ctx := browser(t)
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()

	url := stack.URL() + "/images/1"

	// 1. Land on the detail page; state is "queued" and the scan
	//    button is visible.
	if err := chromedp.Run(ctx,
		chromedp.Navigate(url),
		chromedp.WaitVisible(`.image-detail`, chromedp.ByQuery),
		expectStateText(t, "queued"),
		chromedp.WaitVisible(`button[hx-post$="/images/1/scan"]`, chromedp.ByQuery),
	); err != nil {
		t.Fatalf("setup: %v", err)
	}

	// 2. Click scan.  The action response innerHTML-swaps the detail
	//    section into its "scanning…" intermediate state.
	if err := chromedp.Run(ctx,
		chromedp.Click(`button[hx-post$="/images/1/scan"]`, chromedp.ByQuery),
		chromedp.WaitVisible(`button.busy.scanning`, chromedp.ByQuery),
	); err != nil {
		t.Fatalf("click scan: %v", err)
	}

	// 3. Confirm the SSE channel is live before releasing the scan
	//    goroutine.  EventSource connects asynchronously; without this
	//    handshake, a fast scan can fire its event before the browser
	//    has subscribed and the eventHub silently drops it.
	if err := waitForSSE(ctx, 5*time.Second); err != nil {
		t.Fatalf("SSE never connected: %v", err)
	}

	// 4. Release the scan goroutine.  SaveScan + LogEvent fire, the
	//    mock fans the event onto the SSE hub, and the browser's
	//    listener calls refreshDetail which morphs the section back
	//    into its terminal `scanned` state.  The morph dispatch bug
	//    leaves the state stuck on "queued" indefinitely.
	close(trigger)
	select {
	case <-scanned:
	case <-time.After(5 * time.Second):
		t.Fatalf("scan func never ran")
	}

	if err := waitForStateText(ctx, "scanned", 5*time.Second); err != nil {
		t.Fatalf("state never updated: %v", err)
	}

	// Approve / reject buttons replace the scan button once the
	// transition completes — sanity-check that the action area was
	// re-rendered too, not just the state cell.
	if err := chromedp.Run(ctx,
		chromedp.WaitVisible(`button[hx-post$="/images/1/approve"]`, chromedp.ByQuery),
	); err != nil {
		t.Fatalf("approve button never appeared: %v", err)
	}
}

// expectStateText asserts the meta-row state cell renders the given
// label right now.  Used as a synchronous check after WaitVisible.
func expectStateText(t *testing.T, want string) chromedp.Action {
	t.Helper()
	return chromedp.ActionFunc(func(ctx context.Context) error {
		var got string
		if err := chromedp.Evaluate(stateTextJS, &got).Do(ctx); err != nil {
			return err
		}
		if strings.TrimSpace(got) != want {
			return fmt.Errorf("state = %q, want %q", strings.TrimSpace(got), want)
		}
		return nil
	})
}

// waitForStateText polls the detail-view state cell until it reads
// `want` or the deadline passes.  We can't WaitVisible on the cell
// because morph keeps the same DOM node — only its textContent
// changes — and chromedp's WaitVisible matches against attribute
// changes, not text.
func waitForStateText(ctx context.Context, want string, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		var got string
		if err := chromedp.Run(ctx, chromedp.Evaluate(stateTextJS, &got)); err != nil {
			return err
		}
		if strings.TrimSpace(got) == want {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(100 * time.Millisecond):
		}
	}
	return fmt.Errorf("state never reached %q within %s", want, timeout)
}

// waitForSSE blocks until the EventSource hook installed by the
// harness reports OPEN.  Without this, a fast scan goroutine can
// broadcast its event before the browser has subscribed to /events
// and the eventHub silently drops it.
func waitForSSE(ctx context.Context, timeout time.Duration) error {
	deadline := time.Now().Add(timeout)
	for time.Now().Before(deadline) {
		var ready bool
		if err := chromedp.Run(ctx, chromedp.Evaluate(
			`window.__hermesSSEReady === true`,
			&ready,
		)); err != nil {
			return err
		}
		if ready {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	return fmt.Errorf("SSE never connected within %s", timeout)
}

// stateTextJS reads the meta-row state badge's text.  Wrapped in a
// constant so both the synchronous expectStateText and the polling
// waitForStateText share one selector.
const stateTextJS = `(function () {
	var el = document.querySelector(".image-detail .meta .state");
	return el ? el.textContent : "";
})()`
