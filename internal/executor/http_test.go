package executor

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestHTTPRunnerDeniesRedirectsByDefault(t *testing.T) {
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer final.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL+"/done", http.StatusFound)
	}))
	defer redirect.Close()

	runner := NewHTTPRunner(nil)
	_, err := runner.DoWithPolicy(context.Background(), redirect.URL, HTTPParams{Method: http.MethodGet}, RedirectPolicy{}, 0, 0)
	if !errors.Is(err, ErrRedirectDenied) {
		t.Fatalf("expected ErrRedirectDenied, got %v", err)
	}
}

func TestHTTPRunnerRedirectAllowlistAndFinalResource(t *testing.T) {
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer final.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL+"/done?token=secret", http.StatusFound)
	}))
	defer redirect.Close()

	runner := NewHTTPRunner(nil)
	result, err := runner.DoWithPolicy(context.Background(), redirect.URL, HTTPParams{Method: http.MethodGet}, RedirectPolicy{
		Enabled:    true,
		HopLimit:   2,
		AllowHosts: []string{final.Listener.Addr().String()},
	}, 0, 0)
	if err != nil {
		t.Fatalf("do with policy: %v", err)
	}
	if result.RedirectHops != 1 {
		t.Fatalf("expected 1 redirect hop, got %d", result.RedirectHops)
	}
	if result.FinalResource != "url://"+final.Listener.Addr().String()+"/done" {
		t.Fatalf("expected final resource, got %s", result.FinalResource)
	}
}

func TestHTTPRunnerRejectsRedirectOutsideAllowlist(t *testing.T) {
	final := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("ok"))
	}))
	defer final.Close()
	redirect := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, final.URL+"/done", http.StatusFound)
	}))
	defer redirect.Close()

	runner := NewHTTPRunner(nil)
	_, err := runner.DoWithPolicy(context.Background(), redirect.URL, HTTPParams{Method: http.MethodGet}, RedirectPolicy{
		Enabled:    true,
		AllowHosts: []string{"allowed.example"},
	}, 0, 0)
	if !errors.Is(err, ErrRedirectDisallowedHost) {
		t.Fatalf("expected ErrRedirectDisallowedHost, got %v", err)
	}
}

func TestHTTPRunnerRequiresAllowlistWhenRedirectsEnabled(t *testing.T) {
	runner := NewHTTPRunner(nil)
	_, err := runner.DoWithPolicy(context.Background(), "https://example.com/start", HTTPParams{Method: http.MethodGet}, RedirectPolicy{Enabled: true}, 0, 0)
	if !errors.Is(err, ErrHTTPRedirectAllowlistReq) {
		t.Fatalf("expected ErrHTTPRedirectAllowlistReq, got %v", err)
	}
}

func TestHTTPRunnerCapsRequestAndResponseBodies(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("abcdef"))
	}))
	defer server.Close()

	runner := NewHTTPRunner(nil)
	if _, err := runner.DoWithPolicy(context.Background(), server.URL, HTTPParams{Method: http.MethodPost, Body: "abcdef"}, RedirectPolicy{}, 5, 0); !errors.Is(err, ErrHTTPRequestTooLarge) {
		t.Fatalf("expected ErrHTTPRequestTooLarge, got %v", err)
	}
	result, err := runner.DoWithPolicy(context.Background(), server.URL, HTTPParams{Method: http.MethodGet}, RedirectPolicy{}, 0, 3)
	if err != nil {
		t.Fatalf("do with response cap: %v", err)
	}
	if result.Body != "abc" || !result.Truncated {
		t.Fatalf("expected truncated body abc, got %+v", result)
	}
}
