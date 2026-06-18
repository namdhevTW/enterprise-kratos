package migration

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// FetchSchema — file:// scheme
// ---------------------------------------------------------------------------

func TestFetchSchema_FileSuccess(t *testing.T) {
	want := `{"$schema":"http://json-schema.org/draft-07/schema#","type":"object"}`

	f, err := os.CreateTemp("", "schema-*.json")
	if err != nil {
		t.Fatalf("create temp file: %v", err)
	}
	defer os.Remove(f.Name())
	if _, err := f.WriteString(want); err != nil {
		f.Close()
		t.Fatalf("write temp file: %v", err)
	}
	f.Close()

	got, err := FetchSchema("file://" + f.Name())
	if err != nil {
		t.Fatalf("FetchSchema: unexpected error: %v", err)
	}

	// Normalise by round-tripping through json.RawMessage comparison.
	if string(got) != want {
		t.Errorf("FetchSchema file://: got %s, want %s", got, want)
	}
}

func TestFetchSchema_FileNotFound(t *testing.T) {
	_, err := FetchSchema("file:///nonexistent/path/does-not-exist.json")
	if err == nil {
		t.Fatal("FetchSchema file:// non-existent: expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// FetchSchema — base64:// scheme
// ---------------------------------------------------------------------------

func TestFetchSchema_Base64Success(t *testing.T) {
	original := `{"$schema":"http://json-schema.org/draft-07/schema#"}`
	encoded := base64.StdEncoding.EncodeToString([]byte(original))
	url := "base64://" + encoded

	got, err := FetchSchema(url)
	if err != nil {
		t.Fatalf("FetchSchema base64://: unexpected error: %v", err)
	}
	if string(got) != original {
		t.Errorf("FetchSchema base64://: got %s, want %s", got, original)
	}
}

func TestFetchSchema_Base64InvalidEncoding(t *testing.T) {
	// "!!!" is not valid base64.
	_, err := FetchSchema("base64://!!!not-valid-base64!!!")
	if err == nil {
		t.Fatal("FetchSchema base64:// invalid: expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// FetchSchema — http:// scheme
// ---------------------------------------------------------------------------

func TestFetchSchema_HTTPSuccess(t *testing.T) {
	body := `{"$schema":"http://json-schema.org/draft-07/schema#","title":"test"}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte(body))
	}))
	defer srv.Close()

	got, err := FetchSchema(srv.URL)
	if err != nil {
		t.Fatalf("FetchSchema http://: unexpected error: %v", err)
	}

	// Verify the returned bytes are valid JSON and match what the server sent.
	if !json.Valid(got) {
		t.Errorf("FetchSchema http://: returned bytes are not valid JSON: %s", got)
	}
	if string(got) != body {
		t.Errorf("FetchSchema http://: got %s, want %s", got, body)
	}
}

func TestFetchSchema_HTTPConnectionRefused(t *testing.T) {
	// Port 1 is reserved and will refuse connections on all sane systems.
	_, err := FetchSchema("http://127.0.0.1:1/schema.json")
	if err == nil {
		t.Fatal("FetchSchema http:// connection refused: expected error, got nil")
	}
}

// ---------------------------------------------------------------------------
// FetchSchema — unknown scheme
// ---------------------------------------------------------------------------

func TestFetchSchema_UnknownScheme(t *testing.T) {
	_, err := FetchSchema("ftp://example.com/schema.json")
	if err == nil {
		t.Fatal("FetchSchema unknown scheme: expected error, got nil")
	}
	if !strings.Contains(err.Error(), "unsupported URL scheme") {
		t.Errorf("FetchSchema unknown scheme: error message %q does not contain \"unsupported URL scheme\"", err.Error())
	}
}
