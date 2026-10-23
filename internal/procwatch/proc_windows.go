//go:build windows

package procwatch

import (
	"syscall"
	"unsafe"
)

const (
	th32csSnapProcess = 0x00000002
	maxPath           = 260
)

type processEntry32W struct {
	Size              uint32
	CntUsage          uint32
	ProcessID         uint32
	DefaultHeapID     uintptr
	ModuleID          uint32
	Threads           uint32
	ParentProcessID   uint32
	PriClassBase      int32
	Flags             uint32
	ExeFile           [maxPath]uint16
}

var (
	modKernel32                  = syscall.NewLazyDLL("kernel32.dll")
	procCreateToolhelp32Snapshot = modKernel32.NewProc("CreateToolhelp32Snapshot")
	procProcess32FirstW          = modKernel32.NewProc("Process32FirstW")
	procProcess32NextW           = modKernel32.NewProc("Process32NextW")
)

// listProcessesOS uses the native Windows Kernel32 Toolhelp32 API to walk the process tree
// in microseconds with zero subprocess spawning.
func listProcessesOS() ([]ProcInfo, error) {
	handle, _, err := procCreateToolhelp32Snapshot.Call(uintptr(th32csSnapProcess), 0)
	if handle == uintptr(syscall.InvalidHandle) || handle == 0 {
		return nil, err
	}
	defer syscall.CloseHandle(syscall.Handle(handle))

	var entry processEntry32W
	entry.Size = uint32(unsafe.Sizeof(entry))

	ret, _, err := procProcess32FirstW.Call(handle, uintptr(unsafe.Pointer(&entry)))
	if ret == 0 {
		return nil, err
	}

	procs := make([]ProcInfo, 0, 128)
	for {
		exeName := syscall.UTF16ToString(entry.ExeFile[:])
		procs = append(procs, ProcInfo{
			PID:     int(entry.ProcessID),
			PPID:    int(entry.ParentProcessID),
			Name:    exeName,
			Cmdline: exeName,
		})

		entry.Size = uint32(unsafe.Sizeof(entry))
		ret, _, _ = procProcess32NextW.Call(handle, uintptr(unsafe.Pointer(&entry)))
		if ret == 0 {
			break
		}
	}

	return procs, nil
}
