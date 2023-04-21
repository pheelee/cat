package rlimit

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

// TestNew tests the New function.
func TestNew(t *testing.T) {
	rl := New(10, time.Second)
	if rl.Requests != 10 {
		t.Fatalf("expected %d, got %d", 10, rl.Requests)
	}
	if rl.TimeFrame != time.Second {
		t.Fatalf("expected %s, got %s", time.Second, rl.TimeFrame)
	}
	if rl.IPAccess == nil {
		t.Fatal("expected ip access map, got nil")
	}
}

// TestGetIP tests the getIP function.
func TestGetIP(t *testing.T) {
	r := http.Request{
		RemoteAddr: "",
		Header: http.Header{
			"X-Forwarded-For": []string{"1.2.3.4"},
		},
	}
	if getIP(&r) != "1.2.3.4" {
		t.Fatalf("expected %s, got %s", "1.2.3.4", getIP(&r))
	}

	r.Header.Del("X-Forwarded-For")
	r.RemoteAddr = "5.6.7.8:8080"
	if getIP(&r) != "5.6.7.8" {
		t.Fatalf("expected %s, got %s", "5.6.7.8", getIP(&r))
	}
}

// TestLimit tests the Limit function.
func TestLimit(t *testing.T) {
	rl := New(3, time.Second)
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {})
	h := rl.Limit(next)
	r := http.Request{}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, &r)
	// test if the first response was 200
	if w.Code != http.StatusOK {
		t.Fatalf("expected %d, got %d", http.StatusOK, w.Code)
	}
	// test the rate limit
	for i := 0; i < 4; i++ {
		h.ServeHTTP(w, &r)
	}
	// test if the last response was 429
	if w.Code != http.StatusTooManyRequests {
		t.Fatalf("expected %d, got %d", http.StatusTooManyRequests, w.Code)
	}

	// sleep for 1 second
	time.Sleep(time.Second)
	// test the rate limit again
	for i := 0; i < 10; i++ {
		h.ServeHTTP(w, &r)
	}
}
