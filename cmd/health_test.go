package cmd

import (
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/leshaunj/hermes/internal/config"
)

func TestHealthURL(t *testing.T) {
	cases := map[string]string{
		":8080":        "http://127.0.0.1:8080/healthz",
		"0.0.0.0:8080": "http://127.0.0.1:8080/healthz",
		"[::]:9090":    "http://127.0.0.1:9090/healthz",
		"8080":         "http://127.0.0.1:8080/healthz",
		"":             "http://127.0.0.1:8080/healthz",
	}
	for in, want := range cases {
		if got := healthURL(in); got != want {
			t.Errorf("healthURL(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestHealthProbe_ok(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/healthz" {
			http.NotFound(w, r)
			return
		}
		_, _ = fmt.Fprintln(w, "ok")
	}))
	t.Cleanup(srv.Close)

	if err := healthProbe(srv.URL + "/healthz"); err != nil {
		t.Errorf("healthProbe ok: %v", err)
	}
}

func TestHealthProbe_non200(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Error(w, "down", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)

	err := healthProbe(srv.URL + "/healthz")
	if err == nil {
		t.Fatal("expected error for 500, got nil")
	}
	if !strings.Contains(err.Error(), "500") {
		t.Errorf("error = %v, want status 500 in message", err)
	}
}

func TestHealthProbe_transportError(t *testing.T) {
	// Listen on a port then close, so nothing answers.
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("listen: %v", err)
	}
	addr := ln.Addr().String()
	_ = ln.Close()

	err = healthProbe("http://" + addr + "/healthz")
	if err == nil {
		t.Fatal("expected transport error, got nil")
	}
}

func TestRunHealth_integration(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = fmt.Fprintln(w, "ok")
	}))
	t.Cleanup(srv.Close)

	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatalf("parse url: %v", err)
	}

	cfg = &config.Config{Server: config.ServerConfig{Addr: ":" + u.Port()}}
	t.Cleanup(func() { cfg = nil })

	if err := runHealth(healthCmd, nil); err != nil {
		t.Errorf("runHealth: %v", err)
	}
}
