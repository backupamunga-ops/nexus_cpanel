package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"runtime"

	"github.com/backupamunga-ops/nexus_cpanel/apps/agent/internal/rpc"
)

type healthResult struct {
	Status string `json:"status"`
	Uptime string `json:"uptime"`
}

type infoResult struct {
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Hostname string `json:"hostname"`
	CPUs     int    `json:"cpus"`
}

func (r *Registry) systemHealth(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	return healthResult{Status: "ok", Uptime: uptime()}, nil, nil
}

func (r *Registry) systemInfo(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	h, err := os.Hostname()
	if err != nil {
		h = "unknown"
	}
	return infoResult{
		OS:       runtime.GOOS,
		Arch:     runtime.GOARCH,
		Hostname: h,
		CPUs:     runtime.NumCPU(),
	}, nil, nil
}

var startedAt = nowFunc()

func uptime() string {
	return fmt.Sprintf("%ds", int(nowFunc().Sub(startedAt).Seconds()))
}
