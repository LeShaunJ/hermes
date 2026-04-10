package trivy

import (
	"testing"
)

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

func TestValidateFormat(t *testing.T) {
	for _, f := range SupportedFormats {
		if err := ValidateFormat(f); err != nil {
			t.Errorf("ValidateFormat(%q) unexpected error: %v", f, err)
		}
	}

	unsupported := []string{"xml", "html", "pdf", ""}
	for _, f := range unsupported {
		if err := ValidateFormat(f); err == nil {
			t.Errorf("ValidateFormat(%q) expected error, got nil", f)
		}
	}
}
