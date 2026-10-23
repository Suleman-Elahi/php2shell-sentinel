package service

import "context"

// Runner is the callback invoked when the agent runs in foreground or background service mode.
type Runner func(ctx context.Context) error

// Manager handles OS-specific background service installation, removal, control, and execution.
type Manager struct {
	ServiceName string
	DisplayName string
	Description string
	ExePath     string
	ConfigPath  string
}

// NewManager creates a cross-platform service manager for PHP2Shell Sentinel.
func NewManager(exePath, configPath string) *Manager {
	return &Manager{
		ServiceName: "php2shell-sentinel",
		DisplayName: "PHP2Shell Sentinel Security Agent",
		Description: "Lightweight real-time prevention and containment agent for PHP2Shell (CVE-2026-109618 / CVE-2026-109619)",
		ExePath:     exePath,
		ConfigPath:  configPath,
	}
}
