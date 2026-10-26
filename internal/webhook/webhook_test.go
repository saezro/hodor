package webhook

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestNotifier_DoesNotFollowRedirect: on_change points at server A,
// which 302-redirects to server B. The notification must reach A and
// must never reach B - config.validateOnChange only checks A's
// scheme+host, so following the redirect would let A retarget the
// POST (and its JSON body) at an arbitrary endpoint.
func TestNotifier_DoesNotFollowRedirect(t *testing.T) {
	gotB := make(chan struct{}, 1)
	serverB := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		gotB <- struct{}{}
		w.WriteHeader(http.StatusOK)
	}))
	defer serverB.Close()

	gotA := make(chan struct{}, 1)
	serverA := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotA <- struct{}{}
		http.Redirect(w, r, serverB.URL, http.StatusFound)
	}))
	defer serverA.Close()

	notify := Notifier(serverA.URL, nil)
	notify("test event")

	select {
	case <-gotA:
	case <-time.After(2 * time.Second):
		t.Fatal("server A never received the notification")
	}

	select {
	case <-gotB:
		t.Fatal("server B received the notification: redirect was followed")
	case <-time.After(200 * time.Millisecond):
	}
}

// TestNotifier_EmptyURL_NoOp ensures an empty url (on_change unset)
// returns a no-op rather than panicking or dialing anything.
func TestNotifier_EmptyURL_NoOp(_ *testing.T) {
	notify := Notifier("", nil)
	notify("test event") // must not panic/block
}
