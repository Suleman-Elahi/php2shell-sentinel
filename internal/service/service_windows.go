//go:build windows

package service

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"unsafe"
)

const (
	serviceWin32OwnProcess   = 0x00000010
	serviceStartPending      = 0x00000002
	serviceRunning           = 0x00000004
	serviceStopPending       = 0x00000003
	serviceStopped           = 0x00000001
	serviceAcceptStop        = 0x00000001
	serviceAcceptShutdown    = 0x00000004
	serviceControlStop       = 0x00000001
	serviceControlInterrog   = 0x00000004
	serviceControlShutdown   = 0x00000005
	errorFailedServiceCtrl   = 1063 // ERROR_FAILED_SERVICE_CONTROLLER_CONNECT (running interactively in console)
)

type serviceStatus struct {
	ServiceType             uint32
	CurrentState            uint32
	ControlsAccepted        uint32
	Win32ExitCode           uint32
	ServiceSpecificExitCode uint32
	CheckPoint              uint32
	WaitHint                uint32
}

type serviceTableEntryW struct {
	ServiceName *uint16
	ServiceProc uintptr
}

var (
	modAdvapi32                       = syscall.NewLazyDLL("advapi32.dll")
	procStartServiceCtrlDispatcherW   = modAdvapi32.NewProc("StartServiceCtrlDispatcherW")
	procRegisterServiceCtrlHandlerExW = modAdvapi32.NewProc("RegisterServiceCtrlHandlerExW")
	procSetServiceStatus              = modAdvapi32.NewProc("SetServiceStatus")

	activeRunner     Runner
	activeStatusHdl  uintptr
	activeCancelFunc context.CancelFunc
	activeSvcNamePtr *uint16
)

// UnitFileContent returns the Windows sc.exe registration command for reference.
func (m *Manager) UnitFileContent() string {
	binPath := fmt.Sprintf(`"%s" run`, m.ExePath)
	if m.ConfigPath != "" {
		binPath = fmt.Sprintf(`"%s" run -config "%s"`, m.ExePath, m.ConfigPath)
	}
	return fmt.Sprintf("sc.exe create %s binPath= %q start= auto DisplayName= %q", m.ServiceName, binPath, m.DisplayName)
}

// Install registers PHP2Shell Sentinel with the Windows Service Control Manager (SCM).
func (m *Manager) Install() error {
	binPath := fmt.Sprintf(`"%s" run`, m.ExePath)
	if m.ConfigPath != "" {
		binPath = fmt.Sprintf(`"%s" run -config "%s"`, m.ExePath, m.ConfigPath)
	}
	out, err := exec.Command("sc.exe", "create", m.ServiceName,
		"binPath=", binPath,
		"start=", "auto",
		"DisplayName=", m.DisplayName,
	).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sc.exe create failed: %v (%s)", err, string(out))
	}
	_ = exec.Command("sc.exe", "description", m.ServiceName, m.Description).Run()
	_ = exec.Command("sc.exe", "failure", m.ServiceName, "reset=", "86400", "actions=", "restart/2000/restart/2000/restart/2000").Run()
	return nil
}

// Uninstall stops and deletes the Windows service.
func (m *Manager) Uninstall() error {
	_ = exec.Command("sc.exe", "stop", m.ServiceName).Run()
	out, err := exec.Command("sc.exe", "delete", m.ServiceName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sc.exe delete failed: %v (%s)", err, string(out))
	}
	return nil
}

// Start starts the Windows service via sc.exe.
func (m *Manager) Start() error {
	out, err := exec.Command("sc.exe", "start", m.ServiceName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sc.exe start failed: %v (%s)", err, string(out))
	}
	return nil
}

// Stop stops the Windows service via sc.exe.
func (m *Manager) Stop() error {
	out, err := exec.Command("sc.exe", "stop", m.ServiceName).CombinedOutput()
	if err != nil {
		return fmt.Errorf("sc.exe stop failed: %v (%s)", err, string(out))
	}
	return nil
}

// Status queries the Windows service status via sc.exe.
func (m *Manager) Status() (string, error) {
	out, err := exec.Command("sc.exe", "query", m.ServiceName).CombinedOutput()
	return string(out), err
}

// Run executes the agent as a native Windows Service when started by SCM, or falls back
// automatically to interactive console execution when run from PowerShell/cmd.exe.
func (m *Manager) Run(runner Runner) error {
	activeRunner = runner
	namePtr, err := syscall.UTF16PtrFromString(m.ServiceName)
	if err != nil {
		return err
	}
	activeSvcNamePtr = namePtr

	table := [2]serviceTableEntryW{
		{
			ServiceName: namePtr,
			ServiceProc: syscall.NewCallback(serviceMain),
		},
		{},
	}

	ret, _, callErr := procStartServiceCtrlDispatcherW.Call(uintptr(unsafe.Pointer(&table[0])))
	if ret == 0 {
		// If error is ERROR_FAILED_SERVICE_CONTROLLER_CONNECT (1063), we are running in console mode
		if errno, ok := callErr.(syscall.Errno); ok && errno == errorFailedServiceCtrl {
			ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
			defer stop()
			return runner(ctx)
		}
		return callErr
	}
	return nil
}

func serviceMain(argc uint32, argv **uint16) uintptr {
	hdl, _, _ := procRegisterServiceCtrlHandlerExW.Call(
		uintptr(unsafe.Pointer(activeSvcNamePtr)),
		syscall.NewCallback(serviceCtrlHandler),
		0,
	)
	if hdl == 0 {
		return 0
	}
	activeStatusHdl = hdl

	reportSvcStatus(serviceStartPending, 0, 3000)
	ctx, cancel := context.WithCancel(context.Background())
	activeCancelFunc = cancel

	reportSvcStatus(serviceRunning, serviceAcceptStop|serviceAcceptShutdown, 0)
	_ = activeRunner(ctx)
	reportSvcStatus(serviceStopped, 0, 0)
	return 0
}

func serviceCtrlHandler(control, eventType, eventData, context uintptr) uintptr {
	switch control {
	case serviceControlStop, serviceControlShutdown:
		reportSvcStatus(serviceStopPending, 0, 3000)
		if activeCancelFunc != nil {
			activeCancelFunc()
		}
		return 0
	case serviceControlInterrog:
		return 0
	}
	return 0
}

func reportSvcStatus(state, controlsAccepted, waitHint uint32) {
	st := serviceStatus{
		ServiceType:      serviceWin32OwnProcess,
		CurrentState:     state,
		ControlsAccepted: controlsAccepted,
		WaitHint:         waitHint,
	}
	_, _, _ = procSetServiceStatus.Call(activeStatusHdl, uintptr(unsafe.Pointer(&st)))
}
