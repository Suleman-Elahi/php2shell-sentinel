package waf_test

import (
	"bytes"
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/http/httptest"
	"path"
	"sort"
	"strings"
	"testing"
)

//go:embed testdata/proxy-corpus/*.json
var proxyCorpusFS embed.FS

type proxyCorpusCase struct {
	Name    string            `json:"name"`
	Method  string            `json:"method"`
	Path    string            `json:"path"`
	Headers map[string]string `json:"headers"`
	Body    string            `json:"body"`
	Chunked bool              `json:"chunked"`
	RuleID  string            `json:"rule_id"`
}

func loadProxyCorpus(t *testing.T) []proxyCorpusCase {
	t.Helper()

	entries, err := fs.ReadDir(proxyCorpusFS, "testdata/proxy-corpus")
	if err != nil {
		t.Fatalf("read proxy corpus: %v", err)
	}

	names := make([]string, 0, len(entries))
	for _, entry := range entries {
		if !entry.IsDir() {
			names = append(names, entry.Name())
		}
	}
	sort.Strings(names)

	cases := make([]proxyCorpusCase, 0, len(names))
	for _, name := range names {
		data, err := proxyCorpusFS.ReadFile(path.Join("testdata/proxy-corpus", name))
		if err != nil {
			t.Fatalf("read proxy corpus fixture %s: %v", name, err)
		}

		var fixture proxyCorpusCase
		if err := json.Unmarshal(data, &fixture); err != nil {
			t.Fatalf("parse proxy corpus fixture %s: %v", name, err)
		}
		if fixture.Name == "" || fixture.Method == "" || fixture.Path == "" || fixture.RuleID == "" {
			t.Fatalf("proxy corpus fixture %s is missing required fields", name)
		}
		cases = append(cases, fixture)
	}

	return cases
}

func newCorpusRequest(t *testing.T, fixture proxyCorpusCase, url string) *http.Request {
	t.Helper()

	req := httptest.NewRequest(fixture.Method, url+fixture.Path, bytes.NewBufferString(fixture.Body))
	for key, value := range fixture.Headers {
		req.Header.Set(key, value)
	}
	if fixture.Chunked {
		req.ContentLength = -1
		req.TransferEncoding = []string{"chunked"}
	}
	return req
}

func TestShieldProxy_ProxyCorpus(t *testing.T) {
	shield, _, _ := newTestShield(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusOK)
	})

	for index, fixture := range loadProxyCorpus(t) {
		t.Run(fixture.Name, func(t *testing.T) {
			req := newCorpusRequest(t, fixture, "http://sentinel.test")
			req.RemoteAddr = "198.51.100." + strconvItoa(index+1) + ":12345"
			rec := httptest.NewRecorder()

			shield.ServeHTTP(rec, req)

			if rec.Code != http.StatusForbidden {
				t.Fatalf("status = %d, want %d; body = %s", rec.Code, http.StatusForbidden, rec.Body.String())
			}
			if rule := rec.Header().Get("X-Sentinel-Rule"); !strings.HasPrefix(rule, fixture.RuleID) {
				t.Fatalf("X-Sentinel-Rule = %q, want prefix %q", rule, fixture.RuleID)
			}
		})
	}
}
