//go:build linux

package procwatch

import (
	"bytes"
	"os"
	"strconv"
	"strings"
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
