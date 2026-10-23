package hardener

import (
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"
)

// VersionStatus describes whether a PHP version is vulnerable to php2shell.
type VersionStatus struct {
	RawVersion string `json:"raw_version"`
	Major      int    `json:"major"`
	Minor      int    `json:"minor"`
	Patch      int    `json:"patch"`
	Vulnerable bool   `json:"vulnerable"`
	EOL        bool   `json:"eol"`
	FixedIn    string `json:"fixed_in"`
	Reason     string `json:"reason"`
}

// INIFileReport represents the audit or hardening result for a single php.ini or pool config file.
type INIFileReport struct {
	Path                  string `json:"path"`
	UploadProgressSecured bool   `json:"upload_progress_secured"`
	UseOnlyCookiesSecured bool   `json:"use_only_cookies_secured"`
	Modified              bool   `json:"modified"`
	BackupPath            string `json:"backup_path,omitempty"`
	Error                 string `json:"error,omitempty"`
}

var (
	phpVersionRegex   = regexp.MustCompile(`(\d+)\.(\d+)\.(\d+)`)
	uploadProgressRe  = regexp.MustCompile(`(?i)^\s*session\.upload_progress\.enabled\s*=\s*(.+?)\s*(?:;.*)?$`)
	useOnlyCookiesRe  = regexp.MustCompile(`(?i)^\s*session\.use_only_cookies\s*=\s*(.+?)\s*(?:;.*)?$`)
	fpmPoolProgressRe = regexp.MustCompile(`(?i)^\s*php_(?:admin_)?(?:flag|value)\[session\.upload_progress\.enabled\]\s*=\s*(.+?)\s*(?:;.*)?$`)
)

// CheckPHPVersion determines if a PHP version string (e.g. "8.4.26" or "PHP 8.2.34 (cli)")
// is vulnerable to CVE-2026-109618 and CVE-2026-109619.
func CheckPHPVersion(versionStr string) VersionStatus {
	m := phpVersionRegex.FindStringSubmatch(versionStr)
	if len(m) < 4 {
		return VersionStatus{
			RawVersion: versionStr,
			Vulnerable: true,
			Reason:     "unable to parse version; treat as potentially vulnerable",
		}
	}
	maj, _ := strconv.Atoi(m[1])
	min, _ := strconv.Atoi(m[2])
	pat, _ := strconv.Atoi(m[3])

	st := VersionStatus{
		RawVersion: fmt.Sprintf("%d.%d.%d", maj, min, pat),
		Major:      maj,
		Minor:      min,
		Patch:      pat,
	}

	switch {
	case maj < 5 || (maj == 5 && min < 4):
		st.Vulnerable = false
		st.EOL = true
		st.Reason = "predates PHP 5.4.0 rfc1867 upload_progress, but branch is EOL"
	case maj == 5 || maj == 6 || maj == 7 || (maj == 8 && (min == 0 || min == 1)):
		st.Vulnerable = true
		st.EOL = true
		st.FixedIn = "No official upstream patch (EOL) — disable session.upload_progress.enabled"
		st.Reason = "EOL PHP branch with vulnerable ext/session upload_progress & Zend OOM bailout"
	case maj == 8 && min == 2:
		st.FixedIn = "8.2.35"
		st.Vulnerable = pat < 35
		if st.Vulnerable {
			st.Reason = "PHP 8.2 < 8.2.35 is vulnerable to CVE-2026-109618 / CVE-2026-109619"
		} else {
			st.Reason = "patched (>= 8.2.35)"
		}
	case maj == 8 && min == 3:
		st.FixedIn = "8.3.36"
		st.Vulnerable = pat < 36
		if st.Vulnerable {
			st.Reason = "PHP 8.3 < 8.3.36 is vulnerable to CVE-2026-109618 / CVE-2026-109619"
		} else {
			st.Reason = "patched (>= 8.3.36)"
		}
	case maj == 8 && min == 4:
		st.FixedIn = "8.4.27"
		st.Vulnerable = pat < 27
		if st.Vulnerable {
			st.Reason = "PHP 8.4 < 8.4.27 is vulnerable to CVE-2026-109618 / CVE-2026-109619"
		} else {
			st.Reason = "patched (>= 8.4.27)"
		}
	case maj == 8 && min == 5:
		st.FixedIn = "8.5.12"
		st.Vulnerable = pat < 12
		if st.Vulnerable {
			st.Reason = "PHP 8.5 < 8.5.12 is vulnerable to CVE-2026-109618 / CVE-2026-109619"
		} else {
			st.Reason = "patched (>= 8.5.12)"
		}
	default:
		st.Vulnerable = false
		st.Reason = "newer than affected branches"
	}

	return st
}

// DiscoverINIFiles searches the given root paths for `php.ini`, `.user.ini`, and PHP-FPM pool `.conf` files.
func DiscoverINIFiles(searchRoots []string) []string {
	seen := make(map[string]struct{})
	var files []string

	for _, root := range searchRoots {
		info, err := os.Lstat(root)
		if err != nil {
			continue
		}
		if info.Mode()&os.ModeSymlink != 0 {
			continue
		}
		if !info.IsDir() {
			if isPHPConfigFileName(filepath.Base(root)) {
				seen[root] = struct{}{}
				files = append(files, root)
			}
			continue
		}

		_ = filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			if d.Type()&os.ModeSymlink != 0 {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if d.IsDir() {
				return nil
			}
			if isPHPConfigFileName(d.Name()) {
				if _, ok := seen[path]; !ok {
					seen[path] = struct{}{}
					files = append(files, path)
				}
			}
			return nil
		})
	}
	return files
}

func isPHPConfigFileName(name string) bool {
	lower := strings.ToLower(name)
	if lower == "php.ini" || lower == ".user.ini" {
		return true
	}
	if strings.HasPrefix(lower, "php") && strings.HasSuffix(lower, ".ini") {
		return true
	}
	return false
}

// AuditAndHardenFile inspects a `php.ini` (or `.user.ini`) file and, when apply=true,
// enforces `session.upload_progress.enabled = Off` and `session.use_only_cookies = On`.
func AuditAndHardenFile(path string, apply bool, dryRun bool) INIFileReport {
	rep := INIFileReport{Path: path}

	info, err := os.Lstat(path)
	if err != nil {
		rep.Error = err.Error()
		return rep
	}
	if info.Mode()&os.ModeSymlink != 0 {
		rep.Error = "refusing to modify symlinked configuration file"
		return rep
	}

	raw, err := os.ReadFile(path)
	if err != nil {
		rep.Error = err.Error()
		return rep
	}

	content := string(raw)
	lineEnding := "\n"
	if strings.Contains(content, "\r\n") {
		lineEnding = "\r\n"
	}
	lines := strings.Split(strings.ReplaceAll(content, "\r\n", "\n"), "\n")

	var (
		foundUploadProgress bool
		uploadProgressOff   bool
		foundUseOnlyCookies bool
		useOnlyCookiesOn    bool
	)

	for i, line := range lines {
		if m := uploadProgressRe.FindStringSubmatch(line); len(m) >= 2 {
			foundUploadProgress = true
			if isINIFalse(m[1]) {
				uploadProgressOff = true
			} else {
				uploadProgressOff = false
				if apply {
					lines[i] = "session.upload_progress.enabled = Off"
					rep.Modified = true
				}
			}
		} else if m := fpmPoolProgressRe.FindStringSubmatch(line); len(m) >= 2 {
			foundUploadProgress = true
			if isINIFalse(m[1]) {
				uploadProgressOff = true
			}
		}

		if m := useOnlyCookiesRe.FindStringSubmatch(line); len(m) >= 2 {
			foundUseOnlyCookies = true
			if isINITrue(m[1]) {
				useOnlyCookiesOn = true
			} else {
				useOnlyCookiesOn = false
				if apply {
					lines[i] = "session.use_only_cookies = On"
					rep.Modified = true
				}
			}
		}
	}

	if !foundUploadProgress && apply {
		lines = append(lines,
			"; Added by php2shell-sentinel (CVE-2026-109618 / CVE-2026-109619 mitigation)",
			"session.upload_progress.enabled = Off",
		)
		rep.Modified = true
		uploadProgressOff = true
	}
	if !foundUseOnlyCookies && apply {
		lines = append(lines, "session.use_only_cookies = On")
		rep.Modified = true
		useOnlyCookiesOn = true
	}

	if apply && rep.Modified {
		uploadProgressOff = true
		useOnlyCookiesOn = true
		if !dryRun {
			backupPath := fmt.Sprintf("%s.sentinel-bak-%s", path, time.Now().UTC().Format("20060102-150405"))
			if err := os.WriteFile(backupPath, raw, info.Mode().Perm()); err != nil {
				rep.Error = fmt.Sprintf("backup failed: %v", err)
				return rep
			}
			rep.BackupPath = backupPath

			newContent := strings.Join(lines, lineEnding)
			if err := os.WriteFile(path, []byte(newContent), info.Mode().Perm()); err != nil {
				rep.Error = fmt.Sprintf("write failed: %v", err)
				return rep
			}
		}
	}

	rep.UploadProgressSecured = foundUploadProgress && uploadProgressOff || (apply && rep.Modified)
	rep.UseOnlyCookiesSecured = foundUseOnlyCookies && useOnlyCookiesOn || (apply && rep.Modified)
	return rep
}

func isINIFalse(val string) bool {
	v := strings.ToLower(strings.Trim(strings.TrimSpace(val), `"'`))
	return v == "off" || v == "0" || v == "false" || v == "no" || v == "none" || v == ""
}

func isINITrue(val string) bool {
	v := strings.ToLower(strings.Trim(strings.TrimSpace(val), `"'`))
	return v == "on" || v == "1" || v == "true" || v == "yes"
}
