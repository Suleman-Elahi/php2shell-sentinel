//go:build !linux && !windows

package procwatch

func listProcessesOS() ([]ProcInfo, error) {
	return nil, nil
}
