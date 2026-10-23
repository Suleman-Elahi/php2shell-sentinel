package main

import (
	"bytes"
	"fmt"
	"net/http"
	"os"
	"strings"
	"time"
)

func main() {
	body := "--safe-boundary\r\n" +
		"Content-Disposition: form-data; name=\"PHP_SESSION_UPLOAD_PROGRESS\"\r\n\r\n" +
		"safe-test-marker\r\n" +
		"--safe-boundary--\r\n"

	var resp *http.Response
	var err error
	for i := 0; i < 30; i++ {
		req, reqErr := http.NewRequest(http.MethodPost, "http://sentinel:8080/index.php", bytes.NewBufferString(body))
		if reqErr != nil {
			fmt.Fprintln(os.Stderr, reqErr)
			os.Exit(1)
		}
		req.Header.Set("Content-Type", "multipart/form-data; boundary=safe-boundary")
		resp, err = http.DefaultClient.Do(req)
		if err == nil {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "Sentinel did not become reachable: %v\n", err)
		os.Exit(1)
	}
	defer resp.Body.Close()

	rule := resp.Header.Get("X-Sentinel-Rule")
	blockedBy := resp.Header.Get("X-Blocked-By")
	fmt.Printf("status=%d blocked_by=%q rule=%q\n", resp.StatusCode, blockedBy, rule)

	if resp.StatusCode != http.StatusForbidden ||
		blockedBy != "php2shell-sentinel" ||
		!strings.HasPrefix(rule, "P2S-2026100") {
		fmt.Fprintln(os.Stderr, "expected Sentinel to block the harmless replay")
		os.Exit(1)
	}
}
