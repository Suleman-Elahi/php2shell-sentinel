//go:build linux

package service

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"syscall"
)

const systemdUnitDir = "/etc/systemd/system"

// UnitFileContent generates a hardened Linux systemd unit for the Sentinel daemon.
func (m *Manager) UnitFileContent() string {
	execArgs := fmt.Sprintf("%q run", m.ExePath)
	if m.ConfigPath != "" {
		execArgs = fmt.Sprintf("%q run -config %q", m.ExePath, m.ConfigPath)
	}
	return fmt.Sprintf(`[Unit]
Description=%s
After=network.target

[Service]
Type=simple
ExecStart=%s
Restart=always
RestartSec=2
LimitNOFILE=65535
NoNewPrivileges=yes
ProtectSystem=full

[Install]
WantedBy=multi-user.target
`, m.Description, execArgs)
}

// Install writes the systemd service file, reloads systemd, and enables the service.
func (m *Manager) Install() error {
	unitPath := filepath.Join(systemdUnitDir, m.ServiceName+".service")
	if err := os.WriteFile(unitPath, []byte(m.UnitFileContent()), 0o644); err != nil {
		return fmt.Errorf("write systemd unit %q: %w", unitPath, err)
	}
	if out, err := exec.Command("systemctl", "daemon-reload").CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl daemon-reload: %v (%s)", err, string(out))
	}
	if out, err := exec.Command("systemctl", "enable", m.ServiceName).CombinedOutput(); err != nil {
		return fmt.Errorf("systemctl enable: %v (%s)", err, string(out))
	}
	return nil
}

// Uninstall stops, disables, and removes the systemd service unit.
func (m *Manager) Uninstall() error {
	_ = exec.Command("systemctl", "stop", m.ServiceName).Run()
	_ = exec.Command("systemctl", "disable", m.ServiceName).Run()
	unitPath := filepath.Join(systemdUnitDir, m.ServiceName+".service")
	if err := os.Remove(unitPath); err != nil && !os.IsNotExist(err) {
		return err
	}
	_ = exec.Command("systemctl", "daemon-reload").Run()
	return nil
}

// Start starts the systemd service.
func (m *Manager) Start() error {
	out, err := exec.Command("systemctl", "start", m.ServiceName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl start: %v (%s)", err, string(out))
	}
	return nil
}

// Stop stops the systemd service.
func (m *Manager) Stop() error {
	out, err := exec.Command("systemctl", "stop", m.ServiceName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("systemctl stop: %v (%s)", err, string(out))
	}
	return nil
}

// Status returns the systemd service status output.
func (m *Manager) Status() (string, error) {
	out, err := exec.Command("systemctl", "status", "--no-pager", m.ServiceName).CombinedOutput()
	return string(out), err
}

// Run executes the agent until SIGINT or SIGTERM is received.
func (m *Manager) Run(runner Runner) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runner(ctx)
}
