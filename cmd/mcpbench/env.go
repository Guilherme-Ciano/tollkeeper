package main

import (
	"bufio"
	"context"
	"os"
	"os/exec"
	"runtime"
	"strconv"
	"strings"
)

type environment struct {
	CPU        string `json:"cpu"`
	LogicalCPU int    `json:"logical_cpus"`
	MemGB      int    `json:"mem_gb"`
	Kernel     string `json:"kernel"`
	Governor   string `json:"governor"`
	Boost      string `json:"boost"`
	Go         string `json:"go"`
	Commit     string `json:"commit"`
	Dirty      bool   `json:"dirty"`
	Taskset    bool   `json:"taskset"`
	Note       string `json:"note"`
}

func readTrim(path string) string {
	b, err := os.ReadFile(path)
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(b))
}

func cpuModel() string {
	f, err := os.Open("/proc/cpuinfo")
	if err != nil {
		return runtime.GOARCH
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		if k, v, ok := strings.Cut(s.Text(), ":"); ok && strings.TrimSpace(k) == "model name" {
			return strings.TrimSpace(v)
		}
	}
	return runtime.GOARCH
}

func memGB() int {
	f, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer f.Close()
	s := bufio.NewScanner(f)
	for s.Scan() {
		fields := strings.Fields(s.Text())
		if len(fields) >= 2 && fields[0] == "MemTotal:" {
			kb, err := strconv.Atoi(fields[1])
			if err != nil {
				return 0
			}
			return (kb + 512*1024) / (1024 * 1024)
		}
	}
	return 0
}

func gitOut(ctx context.Context, args ...string) string {
	out, err := exec.CommandContext(ctx, "git", args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

func captureEnv(ctx context.Context, goVersion string, taskset bool) environment {
	return environment{
		CPU:        cpuModel(),
		LogicalCPU: runtime.NumCPU(),
		MemGB:      memGB(),
		Kernel:     readTrim("/proc/sys/kernel/osrelease"),
		Governor:   readTrim("/sys/devices/system/cpu/cpu0/cpufreq/scaling_governor"),
		Boost:      readTrim("/sys/devices/system/cpu/cpufreq/boost"),
		Go:         goVersion,
		Commit:     gitOut(ctx, "rev-parse", "--short", "HEAD"),
		Dirty:      gitOut(ctx, "status", "--porcelain") != "",
		Taskset:    taskset,
		Note:       "same-host loopback, no-op upstream, laptop-class desktop; not internet latency",
	}
}

type procStat struct {
	RSSMB   float64
	CPUSecs float64
}

func readProc(pid int) procStat {
	var st procStat
	status := readTrim("/proc/" + strconv.Itoa(pid) + "/status")
	for line := range strings.SplitSeq(status, "\n") {
		if fields := strings.Fields(line); len(fields) >= 2 && fields[0] == "VmRSS:" {
			kb, err := strconv.ParseFloat(fields[1], 64)
			if err == nil {
				st.RSSMB = kb / 1024
			}
		}
	}
	stat := readTrim("/proc/" + strconv.Itoa(pid) + "/stat")
	if i := strings.LastIndexByte(stat, ')'); i > 0 {
		fields := strings.Fields(stat[i+1:])
		if len(fields) > 13 {
			ut, err1 := strconv.ParseFloat(fields[11], 64)
			sys, err2 := strconv.ParseFloat(fields[12], 64)
			if err1 == nil && err2 == nil {
				st.CPUSecs = (ut + sys) / 100
			}
		}
	}
	return st
}
