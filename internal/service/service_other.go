//go:build !linux && !windows

package service

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"syscall"
)

func (m *Manager) UnitFileContent() string {
	return fmt.Sprintf("%s run -config %s", m.ExePath, m.ConfigPath)
}

func (m *Manager) Install() error {
	return fmt.Errorf("service installation is only supported on Linux (systemd) and Windows (SCM)")
}

func (m *Manager) Uninstall() error {
	return fmt.Errorf("service uninstallation is only supported on Linux (systemd) and Windows (SCM)")
}

func (m *Manager) Start() error {
	return fmt.Errorf("service start is only supported on Linux and Windows")
}

func (m *Manager) Stop() error {
	return fmt.Errorf("service stop is only supported on Linux and Windows")
}

func (m *Manager) Status() (string, error) {
	return "", fmt.Errorf("service status is only supported on Linux and Windows")
}

func (m *Manager) Run(runner Runner) error {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	return runner(ctx)
}
