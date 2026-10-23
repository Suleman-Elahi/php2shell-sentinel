package hardener_test

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/hardener"
)

func TestCheckPHPVersion(t *testing.T) {
	cases := []struct {
		version    string
		vulnerable bool
		eol        bool
	}{
		{"PHP 8.4.26 (cli)", true, false},
		{"PHP 8.4.27 (cli)", false, false},
		{"8.3.35", true, false},
		{"8.3.36", false, false},
		{"8.2.34", true, false},
		{"8.2.35", false, false},
		{"8.5.11", true, false},
		{"8.5.12", false, false},
		{"8.1.34", true, true},
		{"7.4.33", true, true},
		{"5.6.40", true, true},
	}

	for _, tc := range cases {
		st := hardener.CheckPHPVersion(tc.version)
		if st.Vulnerable != tc.vulnerable {
			t.Errorf("version %q: got Vulnerable=%v, want %v", tc.version, st.Vulnerable, tc.vulnerable)
		}
		if st.EOL != tc.eol {
			t.Errorf("version %q: got EOL=%v, want %v", tc.version, st.EOL, tc.eol)
		}
	}
}

func TestAuditAndHardenFile(t *testing.T) {
	dir := t.TempDir()
	iniPath := filepath.Join(dir, "php.ini")
	original := "[Session]\r\nsession.save_handler = files\r\nsession.upload_progress.enabled = On\r\nsession.use_only_cookies = 0\r\n"
	if err := os.WriteFile(iniPath, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}

	// 1. Audit only
	auditRep := hardener.AuditAndHardenFile(iniPath, false, true)
	if auditRep.UploadProgressSecured || auditRep.UseOnlyCookiesSecured {
		t.Fatalf("expected unhardened php.ini to report unsecured: %+v", auditRep)
	}

	// 2. Apply hardening
	hardenRep := hardener.AuditAndHardenFile(iniPath, true, false)
	if !hardenRep.Modified || !hardenRep.UploadProgressSecured || !hardenRep.UseOnlyCookiesSecured {
		t.Fatalf("expected php.ini to be hardened: %+v", hardenRep)
	}
	if hardenRep.BackupPath == "" {
		t.Fatalf("expected backup file to be created")
	}

	updated, err := os.ReadFile(iniPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(updated), "session.upload_progress.enabled = Off") {
		t.Errorf("expected session.upload_progress.enabled = Off in updated php.ini, got:\n%s", string(updated))
	}
	if !strings.Contains(string(updated), "session.use_only_cookies = On") {
		t.Errorf("expected session.use_only_cookies = On in updated php.ini, got:\n%s", string(updated))
	}
}
