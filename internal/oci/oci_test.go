package oci

import (
	"testing"
)

func TestParseRef(t *testing.T) {
	tests := []struct {
		input    string
		registry string
		repo     string
		tag      string
		wantErr  bool
	}{
		{
			input:    "registry.example.com/myapp:v1.2.3",
			registry: "registry.example.com",
			repo:     "myapp",
			tag:      "v1.2.3",
		},
		{
			input:    "quay.io/org/myapp:latest",
			registry: "quay.io",
			repo:     "org/myapp",
			tag:      "latest",
		},
		{
			input:    "docker.io/library/nginx:1.25",
			registry: "index.docker.io",
			repo:     "library/nginx",
			tag:      "1.25",
		},
		{
			// Digest-only refs are not supported.
			input:   "registry.example.com/myapp@sha256:abc123",
			wantErr: true,
		},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			reg, repo, tag, err := ParseRef(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("ParseRef(%q) expected error, got nil", tc.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseRef(%q) unexpected error: %v", tc.input, err)
			}
			if reg != tc.registry {
				t.Errorf("registry = %q, want %q", reg, tc.registry)
			}
			if repo != tc.repo {
				t.Errorf("repository = %q, want %q", repo, tc.repo)
			}
			if tag != tc.tag {
				t.Errorf("tag = %q, want %q", tag, tc.tag)
			}
		})
	}
}

func TestParseChallenge(t *testing.T) {
	tests := []struct {
		input string
		want  map[string]string
	}{
		{
			input: `realm="https://auth.example.com/token",service="registry.example.com",scope="repository:myrepo:pull"`,
			want: map[string]string{
				"realm":   "https://auth.example.com/token",
				"service": "registry.example.com",
				"scope":   "repository:myrepo:pull",
			},
		},
		{
			input: `realm="https://token.docker.io/token",service="registry.docker.io"`,
			want: map[string]string{
				"realm":   "https://token.docker.io/token",
				"service": "registry.docker.io",
			},
		},
		{
			input: "",
			want:  map[string]string{},
		},
	}

	for _, tc := range tests {
		t.Run(tc.input, func(t *testing.T) {
			got := parseChallenge(tc.input)
			for k, v := range tc.want {
				if got[k] != v {
					t.Errorf("param[%q] = %q, want %q", k, got[k], v)
				}
			}
			for k := range got {
				if _, ok := tc.want[k]; !ok {
					t.Errorf("unexpected param %q = %q", k, got[k])
				}
			}
		})
	}
}
