//go:build !linux && !windows

package procwatch

import "os"

func listProcessesOS() ([]ProcInfo, error) {
	return nil, nil
}

func killProcessOS(pid int) error {
	p, err := os.FindProcess(pid)
	if err != nil {
		return err
	}
	return p.Kill()
}
