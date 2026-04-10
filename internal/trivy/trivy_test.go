package trivy

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/leshaunj/hermes/internal/config"
)

// fakeExec returns a function that substitutes execCommand with a real binary
// (echo, cat, false, etc.) so tests never touch Docker.
func fakeExec(name string, fixedArgs ...string) func(string, ...string) *exec.Cmd {
	return func(_ string, _ ...string) *exec.Cmd {
		return exec.Command(name, fixedArgs...)
	}
}

// ── extractJSON ───────────────────────────────────────────────────────────────

func TestExtractJSON(t *testing.T) {
	tests := []struct {
		name    string
		input   []byte
		want    string
		wantErr bool
	}{
		{
			name:  "plain JSON object",
			input: []byte(`{"foo":"bar"}`),
			want:  `{"foo":"bar"}`,
		},
		{
			name:  "JSON with leading log lines",
			input: []byte("2024/01/01 INFO: downloading db\n{\"foo\":\"bar\"}"),
			want:  `{"foo":"bar"}`,
		},
		{
			name:  "JSON with trailing log lines",
			input: []byte("{\"foo\":\"bar\"}\nsome trailing output\n"),
			want:  `{"foo":"bar"}`,
		},
		{
			name:  "JSON with leading and trailing noise",
			input: []byte("noise before\n{\"results\":[]}\ntrailing noise"),
			want:  `{"results":[]}`,
		},
		{
			name:    "no JSON object",
			input:   []byte("no json here at all"),
			wantErr: true,
		},
		{
			name:    "invalid JSON after opening brace",
			input:   []byte("{invalid json}"),
			wantErr: true,
		},
		{
			name:  "nested JSON object",
			input: []byte(`{"a":{"b":1},"c":[1,2,3]}`),
			want:  `{"a":{"b":1},"c":[1,2,3]}`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := extractJSON(tc.input)
			if tc.wantErr {
				if err == nil {
					t.Errorf("expected error, got nil")
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if string(got) != tc.want {
				t.Errorf("got %q, want %q", got, tc.want)
			}
		})
	}
}

// ── ValidateFormat ────────────────────────────────────────────────────────────

func TestValidateFormat(t *testing.T) {
	for _, f := range SupportedFormats {
		if err := ValidateFormat(f); err != nil {
			t.Errorf("ValidateFormat(%q) unexpected error: %v", f, err)
		}
	}
	for _, f := range []string{"xml", "html", "pdf", ""} {
		if err := ValidateFormat(f); err == nil {
			t.Errorf("ValidateFormat(%q) expected error, got nil", f)
		}
	}
}

// ── Scan ──────────────────────────────────────────────────────────────────────

func TestScan_success(t *testing.T) {
	orig := execCommand
	defer func() { execCommand = orig }()
	execCommand = fakeExec("echo", `{"SchemaVersion":2,"Results":[]}`)

	cfg := config.TrivyConfig{Image: "aquasec/trivy:latest"}
	result, err := Scan("registry.example.com/myapp:v1", cfg)
	if err != nil {
		t.Fatalf("Scan() unexpected error: %v", err)
	}
	if len(result.Raw) == 0 {
		t.Error("Scan() returned empty Raw")
	}
}

func TestScan_defaultImage(t *testing.T) {
	orig := execCommand
	defer func() { execCommand = orig }()
	execCommand = fakeExec("echo", `{"SchemaVersion":2}`)

	// Empty Image should default to aquasec/trivy:latest without panicking.
	cfg := config.TrivyConfig{}
	_, err := Scan("myimage:latest", cfg)
	if err != nil {
		t.Fatalf("Scan() with empty Image: %v", err)
	}
}

func TestScan_extraArgs(t *testing.T) {
	orig := execCommand
	defer func() { execCommand = orig }()
	execCommand = fakeExec("echo", `{"SchemaVersion":2}`)

	cfg := config.TrivyConfig{Args: []string{"--ignore-unfixed"}}
	_, err := Scan("myimage:latest", cfg)
	if err != nil {
		t.Fatalf("Scan() with extra args: %v", err)
	}
}

func TestScan_commandFails(t *testing.T) {
	orig := execCommand
	defer func() { execCommand = orig }()
	// "false" exits with non-zero status.
	execCommand = fakeExec("false")

	cfg := config.TrivyConfig{}
	_, err := Scan("myimage:latest", cfg)
	if err == nil {
		t.Error("Scan() expected error from failing command, got nil")
	}
}

func TestScan_noJSON(t *testing.T) {
	orig := execCommand
	defer func() { execCommand = orig }()
	execCommand = fakeExec("echo", "no json output here")

	cfg := config.TrivyConfig{}
	_, err := Scan("myimage:latest", cfg)
	if err == nil {
		t.Error("Scan() expected error when no JSON, got nil")
	}
}

// ── Convert ───────────────────────────────────────────────────────────────────

func TestConvert_success(t *testing.T) {
	orig := execCommand
	defer func() { execCommand = orig }()
	execCommand = fakeExec("echo", "converted output")

	cfg := config.TrivyConfig{Image: "aquasec/trivy:latest"}
	out, err := Convert([]byte(`{"SchemaVersion":2}`), "table", cfg)
	if err != nil {
		t.Fatalf("Convert() unexpected error: %v", err)
	}
	if len(out) == 0 {
		t.Error("Convert() returned empty output")
	}
}

func TestConvert_defaultImage(t *testing.T) {
	orig := execCommand
	defer func() { execCommand = orig }()
	execCommand = fakeExec("echo", "output")

	cfg := config.TrivyConfig{}
	_, err := Convert([]byte(`{}`), "sarif", cfg)
	if err != nil {
		t.Fatalf("Convert() with empty Image: %v", err)
	}
}

func TestConvert_extraArgs(t *testing.T) {
	orig := execCommand
	defer func() { execCommand = orig }()
	execCommand = fakeExec("echo", "output")

	cfg := config.TrivyConfig{ConvertArgs: []string{"--template", "@tmpl.tpl"}}
	_, err := Convert([]byte(`{}`), "template", cfg)
	if err != nil {
		t.Fatalf("Convert() with ConvertArgs: %v", err)
	}
}

func TestConvert_commandFails(t *testing.T) {
	orig := execCommand
	defer func() { execCommand = orig }()
	execCommand = fakeExec("false")

	cfg := config.TrivyConfig{}
	_, err := Convert([]byte(`{}`), "table", cfg)
	if err == nil {
		t.Error("Convert() expected error from failing command, got nil")
	}
}

// ── ConvertToFile ─────────────────────────────────────────────────────────────

func TestConvertToFile_stdout(t *testing.T) {
	orig := execCommand
	defer func() { execCommand = orig }()
	execCommand = fakeExec("echo", "table output")

	cfg := config.TrivyConfig{}
	if err := ConvertToFile([]byte(`{}`), "table", "-", cfg); err != nil {
		t.Fatalf("ConvertToFile(-): %v", err)
	}
}

func TestConvertToFile_file(t *testing.T) {
	orig := execCommand
	defer func() { execCommand = orig }()
	execCommand = fakeExec("echo", "sarif output")

	cfg := config.TrivyConfig{}
	outPath := filepath.Join(t.TempDir(), "report.sarif")
	if err := ConvertToFile([]byte(`{}`), "sarif", outPath, cfg); err != nil {
		t.Fatalf("ConvertToFile(file): %v", err)
	}
	b, err := os.ReadFile(outPath)
	if err != nil {
		t.Fatalf("read output file: %v", err)
	}
	if len(b) == 0 {
		t.Error("output file is empty")
	}
}

func TestConvertToFile_empty_path_writes_stdout(t *testing.T) {
	orig := execCommand
	defer func() { execCommand = orig }()
	execCommand = fakeExec("echo", "output")

	cfg := config.TrivyConfig{}
	// empty outPath should behave like "-"
	if err := ConvertToFile([]byte(`{}`), "table", "", cfg); err != nil {
		t.Fatalf("ConvertToFile(empty): %v", err)
	}
}

func TestConvertToFile_convertError(t *testing.T) {
	orig := execCommand
	defer func() { execCommand = orig }()
	execCommand = fakeExec("false")

	cfg := config.TrivyConfig{}
	err := ConvertToFile([]byte(`{}`), "table", "/tmp/out.txt", cfg)
	if err == nil {
		t.Error("ConvertToFile() expected error from failing convert, got nil")
	}
}
