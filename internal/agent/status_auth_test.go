package agent

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/config"
)

func TestAuthorizeStatus(t *testing.T) {
	ag := &Agent{cfg: &config.Config{StatusAuthToken: "test-token"}}

	t.Run("rejects requests without bearer token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/status", nil)
		rec := httptest.NewRecorder()

		if ag.authorizeStatus(rec, req) {
			t.Fatal("authorizeStatus() = true, want false")
		}
		if rec.Code != http.StatusUnauthorized {
			t.Fatalf("status = %d, want %d", rec.Code, http.StatusUnauthorized)
		}
	})

	t.Run("accepts requests with the configured bearer token", func(t *testing.T) {
		req := httptest.NewRequest(http.MethodGet, "/status", nil)
		req.Header.Set("Authorization", "Bearer test-token")
		rec := httptest.NewRecorder()

		if !ag.authorizeStatus(rec, req) {
			t.Fatal("authorizeStatus() = false, want true")
		}
	})
}

func TestHandleBansDisablesWritesWithoutToken(t *testing.T) {
	ag := &Agent{cfg: config.Default()}
	req := httptest.NewRequest(http.MethodDelete, "/bans?ip=192.0.2.1", nil)
	rec := httptest.NewRecorder()

	ag.handleBans(rec, req)

	if rec.Code != http.StatusForbidden {
		t.Fatalf("status = %d, want %d", rec.Code, http.StatusForbidden)
	}
}
