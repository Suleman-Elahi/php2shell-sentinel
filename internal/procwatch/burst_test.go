package procwatch_test

import (
	"context"
	"io"
	"sync/atomic"
	"testing"
	"time"

	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/audit"
	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/config"
	"github.com/legacy-php-sentinel/php2shell-sentinel/internal/procwatch"
)

// TestWatcher_TriggerBurstIncreasesSamplingRate verifies that a WAF-driven
// suspicion hint switches the watchdog from its normal polling cadence to the
// fast burst cadence, closing the short-lived-process sampling gap.
func TestWatcher_TriggerBurstIncreasesSamplingRate(t *testing.T) {
	cfg := config.Default()
	cfg.ProcPollInterval = 500 * time.Millisecond
	cfg.ProcBurstInterval = 2 * time.Millisecond
	cfg.ProcBurstWindow = 300 * time.Millisecond

	logger := audit.NewBufferLogger(io.Discard, "json")
	watcher := procwatch.NewWatcher(cfg, logger)

	var scans atomic.Int64
	watcher.SetEnumeratorAndKiller(
		func() ([]procwatch.ProcInfo, error) {
			scans.Add(1)
			return nil, nil
		},
		func(int) error { return nil },
	)

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go watcher.Run(ctx)

	deadline := time.Now().Add(2 * time.Second)
	for scans.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if scans.Load() == 0 {
		t.Fatal("watcher did not perform an initial scan")
	}

	before := scans.Load()
	watcher.TriggerBurst()
	time.Sleep(100 * time.Millisecond)
	after := scans.Load()

	// With a 500ms base interval only the initial scan would have happened in
	// this window; burst mode at 2ms should add dozens.
	if delta := after - before; delta < 5 {
		t.Fatalf("expected burst sampling to add scans, got %d (before=%d after=%d)", delta, before, after)
	}
}
