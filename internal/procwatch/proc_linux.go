//go:build linux

package procwatch

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func listProcessesOS() ([]ProcInfo, error) {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil, err
	}

	pageSizeKB := uint64(os.Getpagesize() / 1024)
	if pageSizeKB == 0 {
		pageSizeKB = 4
	}

	procs := make([]ProcInfo, 0, len(entries)/2)
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if len(name) == 0 || name[0] < '0' || name[0] > '9' {
			continue
		}
		pid, err := strconv.Atoi(name)
		if err != nil || pid <= 0 {
			continue
		}

		statPath := "/proc/" + name + "/stat"
		statData, err := os.ReadFile(statPath)
		if err != nil {
			continue
		}

		comm, ppid, rssPages, ok := parseProcStat(statData)
		if !ok {
			continue
		}

		cmdline := comm
		if cmdBytes, err := os.ReadFile("/proc/" + name + "/cmdline"); err == nil && len(cmdBytes) > 0 {
			cleaned := bytes.ReplaceAll(bytes.TrimRight(cmdBytes, "\x00"), []byte{0}, []byte{' '})
			cmdline = string(cleaned)
		}

		procs = append(procs, ProcInfo{
			PID:     pid,
			PPID:    ppid,
			Name:    comm,
			Cmdline: cmdline,
			RSSKB:   rssPages * pageSizeKB,
		})
	}
	return procs, nil
}

// parseProcStat parses `/proc/[pid]/stat` safely even when comm contains spaces or parentheses.
func parseProcStat(data []byte) (comm string, ppid int, rssPages uint64, ok bool) {
	openParen := bytes.IndexByte(data, '(')
	closeParen := bytes.LastIndexByte(data, ')')
	if openParen < 0 || closeParen <= openParen || closeParen+2 >= len(data) {
		return "", 0, 0, false
	}
	comm = string(data[openParen+1 : closeParen])
	rest := strings.Fields(string(data[closeParen+2:]))
	// Field index after `(comm)`:
	// 0: state, 1: ppid, ..., 21: rss (in pages)
	if len(rest) < 22 {
		return "", 0, 0, false
	}
	ppidVal, err := strconv.Atoi(rest[1])
	if err != nil {
		return "", 0, 0, false
	}
	rssVal, _ := strconv.ParseUint(rest[21], 10, 64)
	return comm, ppidVal, rssVal, true
}

// killProcessOS freezes the target process with SIGSTOP so it cannot fork or exit
// (preventing the kernel from re-parenting its children to PID 1 while we inspect it),
// recursively collects any live child PIDs from /proc/<pid>/task/*/children, kills
// the process group if pid is a process group leader, and SIGKILLs all descendants and pid.
func killProcessOS(pid int) error {
	if pid <= 1 {
		return syscall.EINVAL
	}
	selfPID := os.Getpid()
	visited := make(map[int]struct{}, 8)
	descendants := collectAndStopLinuxDescendants(pid, selfPID, visited)

	// If the target process created its own process group (PGID == PID), kill the whole group.
	if pgid, err := syscall.Getpgid(pid); err == nil && pgid == pid && pgid > 1 && pgid != selfPID {
		_ = syscall.Kill(-pgid, syscall.SIGKILL)
	}

	// Kill descendants before/alongside the parent so none survive as orphans under init (PID 1).
	for _, childPID := range descendants {
		if childPID > 1 && childPID != selfPID {
			_ = syscall.Kill(childPID, syscall.SIGKILL)
		}
	}

	return syscall.Kill(pid, syscall.SIGKILL)
}

func collectAndStopLinuxDescendants(pid, selfPID int, visited map[int]struct{}) []int {
	if pid <= 1 || pid == selfPID {
		return nil
	}
	if _, seen := visited[pid]; seen {
		return nil
	}
	visited[pid] = struct{}{}

	// Freeze the process before inspecting its children so it cannot fork new children or exit.
	_ = syscall.Kill(pid, syscall.SIGSTOP)

	children := readLinuxTaskChildren(pid)
	var out []int
	for _, childPID := range children {
		if childPID <= 1 || childPID == selfPID {
			continue
		}
		out = append(out, childPID)
		out = append(out, collectAndStopLinuxDescendants(childPID, selfPID, visited)...)
	}
	return out
}

func readLinuxTaskChildren(pid int) []int {
	taskDir := "/proc/" + strconv.Itoa(pid) + "/task"
	entries, err := os.ReadDir(taskDir)
	if err != nil {
		return nil
	}
	var children []int
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		childrenPath := filepath.Join(taskDir, entry.Name(), "children")
		data, err := os.ReadFile(childrenPath)
		if err != nil || len(data) == 0 {
			continue
		}
		for _, field := range strings.Fields(string(data)) {
			if childPID, err := strconv.Atoi(field); err == nil && childPID > 1 {
				children = append(children, childPID)
			}
		}
	}
	return children
}
