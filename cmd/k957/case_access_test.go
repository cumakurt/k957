package main

import (
	"net/http/httptest"
	"strings"
	"testing"
)

func TestCaseViewerAuthorityTokenAndOrigin(t *testing.T) {
	h := caseViewerHandler("absent", "127.0.0.1:9876", "session-token")
	for _, tc := range []struct {
		target, host, origin string
		status               int
	}{
		{"/?token=session-token", "127.0.0.1:9876", "", 200},
		{"/?token=wrong", "127.0.0.1:9876", "", 403},
		{"/?token=session-token", "attacker.example:9876", "", 403},
		{"/?token=session-token", "127.0.0.1:9876", "https://attacker.example", 403},
	} {
		r := httptest.NewRequest("GET", tc.target, nil)
		r.Host = tc.host
		r.Header.Set("Origin", tc.origin)
		w := httptest.NewRecorder()
		h.ServeHTTP(w, r)
		if w.Code != tc.status {
			t.Fatalf("%+v: %d", tc, w.Code)
		}
		if w.Header().Get("Cache-Control") != "no-store" {
			t.Fatal("sensitive response may be cached")
		}
	}
	if strings.Contains(caseViewerScript, "innerHTML") {
		t.Fatal("evidence is rendered as HTML")
	}
	r := httptest.NewRequest("POST", "/?token=session-token", nil)
	r.Host = "127.0.0.1:9876"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != 405 {
		t.Fatal("viewer accepts writes")
	}
}
