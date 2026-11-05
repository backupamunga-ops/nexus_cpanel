package commands

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/backupamunga-ops/nexus_cpanel/apps/agent/internal/rpc"
)

// php.* (agent spec §4.6) — per-site PHP-FPM pool management.
//
// A pool is one file under PhpRoot/<version>/pools/<domain>.conf. The agent
// RENDERS the pool from a strictly-decoded config object (the
// DisallowUnknownFields boundary pattern from account.quota: the agent must
// understand everything it is told to enforce) and returns the applied
// content, so the control plane's config_versions history records the
// exact bytes on disk.
//
// php.install_version is deliberately a precondition: installing PHP
// versions means apt/dnf package operations — that is the installer's and
// the node operator's job, not a signed-command away.

const maxPoolsPerVersion = 512

var phpVersionRe = regexp.MustCompile(`^8\.[1-4]$`)

// poolSpec is the canonical, strictly-decoded pool configuration.
type poolSpec struct {
	Pm                *string `json:"pm"`               // dynamic | static | ondemand
	PmMaxChildren     *int    `json:"pm.max_children"`  // 1..500
	PmStartServers    *int    `json:"pm.start_servers"` // 1..100
	PmMinSpareServers *int    `json:"pm.min_spare_servers"`
	PmMaxSpareServers *int    `json:"pm.max_spare_servers"`
	MemoryLimit       *string `json:"memory_limit"`        // e.g. "128M"
	UploadMaxFilesize *string `json:"upload_max_filesize"` // e.g. "32M"
	MaxExecutionTime  *int    `json:"max_execution_time"`  // seconds, 1..300
}

func decodePoolStrict(raw json.RawMessage) (*poolSpec, error) {
	dec := json.NewDecoder(strings.NewReader(string(raw)))
	dec.DisallowUnknownFields()
	var p poolSpec
	if err := dec.Decode(&p); err != nil {
		return nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "config: " + err.Error()}
	}
	return &p, nil
}

var phpSizeRe = regexp.MustCompile(`^\d{1,5}[MG]$`)

func validatePoolSpec(p *poolSpec) error {
	if p.Pm != nil {
		switch *p.Pm {
		case "dynamic", "static", "ondemand":
		default:
			return &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "config.pm must be dynamic | static | ondemand"}
		}
	}
	for name, v := range map[string]*int{
		"pm.max_children":      p.PmMaxChildren,
		"pm.start_servers":     p.PmStartServers,
		"pm.min_spare_servers": p.PmMinSpareServers,
		"pm.max_spare_servers": p.PmMaxSpareServers,
	} {
		if v == nil {
			continue
		}
		if *v < 1 || *v > 500 {
			return &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: fmt.Sprintf("config.%s must be 1..500", name)}
		}
	}
	for name, v := range map[string]*string{"memory_limit": p.MemoryLimit, "upload_max_filesize": p.UploadMaxFilesize} {
		if v == nil {
			continue
		}
		if !phpSizeRe.MatchString(*v) {
			return &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: fmt.Sprintf("config.%s must look like '128M' or '1G'", name)}
		}
	}
	if p.MaxExecutionTime != nil && (*p.MaxExecutionTime < 1 || *p.MaxExecutionTime > 300) {
		return &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "config.max_execution_time must be 1..300 seconds"}
	}
	return nil
}

// renderPool renders the pool file. Values are pre-validated; the renderer
// only formats. versionDirSuffix keeps sockets unique per PHP version.
func renderPool(username, domain, version string, p *poolSpec) string {
	var b strings.Builder
	fmt.Fprintf(&b, "; managed by nexuspanel — do not edit\n[%s]\n", domain)
	fmt.Fprintf(&b, "user = %s\n", username)
	fmt.Fprintf(&b, "group = %s\n", username)
	fmt.Fprintf(&b, "listen = /run/php/php%s-fpm-%s.sock\n", version, domain)
	pm := "dynamic"
	if p.Pm != nil {
		pm = *p.Pm
	}
	fmt.Fprintf(&b, "pm = %s\n", pm)
	if p.PmMaxChildren != nil {
		fmt.Fprintf(&b, "pm.max_children = %d\n", *p.PmMaxChildren)
	}
	if p.PmStartServers != nil {
		fmt.Fprintf(&b, "pm.start_servers = %d\n", *p.PmStartServers)
	}
	if p.PmMinSpareServers != nil {
		fmt.Fprintf(&b, "pm.min_spare_servers = %d\n", *p.PmMinSpareServers)
	}
	if p.PmMaxSpareServers != nil {
		fmt.Fprintf(&b, "pm.max_spare_servers = %d\n", *p.PmMaxSpareServers)
	}
	if p.MemoryLimit != nil {
		fmt.Fprintf(&b, "php_admin_value[memory_limit] = %s\n", *p.MemoryLimit)
	}
	if p.UploadMaxFilesize != nil {
		fmt.Fprintf(&b, "php_admin_value[upload_max_filesize] = %s\n", *p.UploadMaxFilesize)
	}
	if p.MaxExecutionTime != nil {
		fmt.Fprintf(&b, "php_admin_value[max_execution_time] = %d\n", *p.MaxExecutionTime)
	}
	return b.String()
}

type poolResult struct {
	Status      string `json:"status"` // applied | removed
	Version     string `json:"version,omitempty"`
	PoolFile    string `json:"pool_file,omitempty"`
	ConfContent string `json:"conf_content,omitempty"`
}

type createPoolParams struct {
	Username string          `json:"username"`
	Domain   string          `json:"domain"`
	Version  string          `json:"version"`
	Config   json.RawMessage `json:"config"`
}

// poolDir returns the pools dir for a version, verifying the version is
// actually installed on this node (the version dir IS the installation
// record — no version dir, no pool).
func (r *Registry) poolDir(version string) (string, error) {
	if !phpVersionRe.MatchString(version) {
		return "", &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "version must be one of 8.1..8.4"}
	}
	dir := filepath.Join(r.deps.PhpRoot, version, "pools")
	if fi, err := os.Stat(filepath.Join(r.deps.PhpRoot, version)); err != nil || !fi.IsDir() {
		return "", &rpc.RPCError{
			Code:    rpc.CodePrecondition,
			Message: fmt.Sprintf("PHP %s is not installed on this node (install_version is an operator task)", version),
		}
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		return "", &rpc.RPCError{Code: rpc.CodeInternalError, Message: fmt.Sprintf("pools mkdir failed: %v", err)}
	}
	return dir, nil
}

func (r *Registry) phpCreatePool(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p createPoolParams
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	if !usernameRe.MatchString(p.Username) || reservedNames[p.Username] {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid username"}
	}
	if !fqdnRe.MatchString(p.Domain) || len(p.Domain) > 253 {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid domain"}
	}
	dir, err := r.poolDir(p.Version)
	if err != nil {
		return nil, nil, err
	}
	spec, err := decodePoolStrict(p.Config)
	if err != nil {
		return nil, nil, err
	}
	if err := validatePoolSpec(spec); err != nil {
		return nil, nil, err
	}
	if err := r.assertNotOverPoolCap(dir); err != nil {
		return nil, nil, err
	}

	poolFile := filepath.Join(dir, p.Domain+".conf")
	if _, err := os.Stat(poolFile); err == nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeConflict, Message: "pool already exists for this domain (modify instead)"}
	}
	conf := renderPool(p.Username, p.Domain, p.Version, spec)
	if err := os.WriteFile(poolFile, []byte(conf), 0o644); err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: fmt.Sprintf("pool write failed: %v", err)}
	}

	entry := r.deps.WAL.NewEntry("php.create_pool", map[string]any{
		"username": p.Username, "domain": p.Domain, "version": p.Version,
	})
	_ = r.deps.WAL.Append(entry)
	return poolResult{Status: "applied", Version: p.Version, PoolFile: poolFile, ConfContent: conf}, auditQueued(entry), nil
}

func (r *Registry) phpModifyPool(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p createPoolParams
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	if !usernameRe.MatchString(p.Username) || reservedNames[p.Username] {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid username"}
	}
	if !fqdnRe.MatchString(p.Domain) || len(p.Domain) > 253 {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid domain"}
	}
	dir, err := r.poolDir(p.Version)
	if err != nil {
		return nil, nil, err
	}
	spec, err := decodePoolStrict(p.Config)
	if err != nil {
		return nil, nil, err
	}
	if err := validatePoolSpec(spec); err != nil {
		return nil, nil, err
	}

	poolFile := filepath.Join(dir, p.Domain+".conf")
	if _, err := os.Stat(poolFile); err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "pool does not exist for this domain (create first)"}
	}
	conf := renderPool(p.Username, p.Domain, p.Version, spec)
	if err := os.WriteFile(poolFile, []byte(conf), 0o644); err != nil {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: fmt.Sprintf("pool write failed: %v", err)}
	}

	entry := r.deps.WAL.NewEntry("php.modify_pool", map[string]any{
		"username": p.Username, "domain": p.Domain, "version": p.Version,
	})
	_ = r.deps.WAL.Append(entry)
	return poolResult{Status: "applied", Version: p.Version, PoolFile: poolFile, ConfContent: conf}, auditQueued(entry), nil
}

func (r *Registry) phpDeletePool(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	var p struct {
		Username string `json:"username"`
		Domain   string `json:"domain"`
		Version  string `json:"version"`
	}
	if err := decodeParams(raw, &p); err != nil {
		return nil, nil, err
	}
	if !usernameRe.MatchString(p.Username) || reservedNames[p.Username] {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid username"}
	}
	if !fqdnRe.MatchString(p.Domain) || len(p.Domain) > 253 {
		return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid domain"}
	}
	dir, err := r.poolDir(p.Version)
	if err != nil {
		return nil, nil, err
	}
	poolFile := filepath.Join(dir, p.Domain+".conf")
	existed := false
	if _, err := os.Stat(poolFile); err == nil {
		existed = true
		if err := os.Remove(poolFile); err != nil {
			return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: fmt.Sprintf("pool remove failed: %v", err)}
		}
	}
	entry := r.deps.WAL.NewEntry("php.delete_pool", map[string]any{
		"username": p.Username, "domain": p.Domain, "version": p.Version, "existed": existed,
	})
	_ = r.deps.WAL.Append(entry)
	return poolResult{Status: "removed", Version: p.Version}, auditQueued(entry), nil
}

type listVersionsResult struct {
	Installed []string `json:"installed"`
	// Pools maps domain → pool file per installed version is the node's
	// view; the control plane's config_versions is the managed view.
}

// phpListVersions reports PHP versions installed on this node (the version
// dirs under PhpRoot). install_version stays an operator task.
func (r *Registry) phpListVersions(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
	out := []string{}
	dirEntries, err := os.ReadDir(r.deps.PhpRoot)
	if err == nil {
		for _, de := range dirEntries {
			if de.IsDir() && phpVersionRe.MatchString(de.Name()) {
				out = append(out, de.Name())
			}
		}
	}
	sort.Strings(out)
	return listVersionsResult{Installed: out}, nil, nil
}

// assertNotOverPoolCap keeps one runaway control plane from filing a
// directory with unlimited pools (each pool is a process group).
func (r *Registry) assertNotOverPoolCap(dir string) error {
	dirEntries, err := os.ReadDir(dir)
	if err != nil {
		return nil // pools dir does not exist yet — creating it is fine
	}
	if len(dirEntries) >= maxPoolsPerVersion {
		return &rpc.RPCError{
			Code:    rpc.CodeQuota,
			Message: fmt.Sprintf("pool cap reached for this version (%d)", maxPoolsPerVersion),
		}
	}
	return nil
}
