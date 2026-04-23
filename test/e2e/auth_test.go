//go:build e2e

package e2e

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
)

// upstreamAuth is a minimal bearer-auth middleware that wraps an OCI
// registry handler.  It issues a WWW-Authenticate challenge on
// unauthenticated /v2/ requests, issues a stub token from /token, and
// accepts any "Bearer <anything>" on every other path.  The goal is to
// force hermes and the OCI client through the full token-acquisition
// flow so header-rewriting and proxy bugs surface at test time.
type upstreamAuth struct {
	service string
	base    string // set by the harness once httptest picks a port
}

func newUpstreamAuth() *upstreamAuth {
	return &upstreamAuth{service: "hermes-e2e"}
}

func (a *upstreamAuth) wrap(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/token" {
			a.serveToken(w, r)
			return
		}
		// Challenge the discovery endpoints hermes's challengeRetrieve
		// probes (/v2/ and /v2/<repo>/tags/list) when no bearer is set.
		// Streaming paths (blob uploads, PATCH/PUT) are left alone so a
		// mid-body 401 never interrupts an upload — clients authenticate
		// up front before pushing.
		isDiscovery := r.URL.Path == "/v2/" ||
			r.URL.Path == "/v2" ||
			strings.HasSuffix(r.URL.Path, "/tags/list")
		if isDiscovery && !hasBearer(r) {
			a.challenge(w)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (a *upstreamAuth) challenge(w http.ResponseWriter) {
	w.Header().Set("WWW-Authenticate",
		fmt.Sprintf(`Bearer realm="%s/token",service="%s"`, a.base, a.service))
	w.Header().Set("Docker-Distribution-API-Version", "registry/2.0")
	w.WriteHeader(http.StatusUnauthorized)
	_ = json.NewEncoder(w).Encode(map[string]any{
		"errors": []map[string]string{{"code": "UNAUTHORIZED", "message": "auth required"}},
	})
}

func (a *upstreamAuth) serveToken(w http.ResponseWriter, _ *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{
		"token":        "stub-token",
		"access_token": "stub-token",
	})
}

func hasBearer(r *http.Request) bool {
	return strings.HasPrefix(r.Header.Get("Authorization"), "Bearer ")
}
