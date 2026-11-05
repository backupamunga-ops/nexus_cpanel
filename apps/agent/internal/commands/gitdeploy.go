package commands

import (
        "encoding/json"
        "fmt"
        "os"
        "os/exec"
        "path/filepath"
        "regexp"
        "sort"
        "strconv"
        "strings"
        "time"

        "github.com/backupamunga-ops/nexus_cpanel/apps/agent/internal/rpc"
)

// git.* (ADR-0019 amendment to agent spec §4) — B14: push-to-deploy.
//
// Release model: every deploy clones/checks out into
// <home>/.nexus-git/<domain>/releases/<unix-ts>-<sha7>/ and the deploy
// path becomes an ATOMIC SYMLINK to the active release. The releases
// directory IS the deploy history — `git.deploy_history` reads it, and
// `git.rollback` re-points the symlink to an older release. Nothing is
// ever deleted by deploys; pruning is a separate, explicit flow.
//
// Safety: GIT_TERMINAL_PROMPT=0 (a hung clone can never wait for input),
// repo URLs are https/ssh only, the deploy path must be absent or a
// symlink (a real populated docroot is never silently replaced), and the
// checkout is best-effort chowned to the account user.

const (
        gitReleasesDir = ".nexus-git"
        maxGitRepos    = 20 // per call surface; history stays full
)

var (
        gitRepoRe   = regexp.MustCompile(`^(https://[^\s@/]+/[^\s@]+/[^\s@]+\.git|git@[a-zA-Z0-9.-]+:[^\s/]+/[^\s]+\.git)$`)
        gitBranchRe = regexp.MustCompile(`^[a-zA-Z0-9._/-]{1,128}$`)
        gitShaRe    = regexp.MustCompile(`^[0-9a-f]{7,40}$`)
        releaseRe   = regexp.MustCompile(`^([0-9]{10,12})-([0-9a-f]{7,40})(?:-([0-9]+))?$`)
)

type gitDeployParams struct {
        Username   string `json:"username"`
        Domain     string `json:"domain"`
        RepoURL    string `json:"repo_url"`
        Branch     string `json:"branch"`
        Sha        string `json:"sha"`
        DeployPath string `json:"deploy_path"`
}

type gitDeployResult struct {
        Status    string `json:"status"`
        ReleaseID string `json:"release_id"`
        Sha       string `json:"sha"`
        Path      string `json:"path"`
        Log       string `json:"log"`
}

type gitRelease struct {
        ReleaseID string `json:"release_id"`
        Sha       string `json:"sha"`
        CreatedAt string `json:"created_at"`
        Active    bool   `json:"active"`
}

type gitHistoryResult struct {
        Releases []gitRelease `json:"releases"`
        Current  string       `json:"current"`
        Path     string       `json:"path"`
}

func (r *Registry) gitBinary() (string, error) {
        if r.deps.GitBinary != "" {
                return r.deps.GitBinary, nil
        }
        bin, err := exec.LookPath("git")
        if err != nil {
                return "", &rpc.RPCError{
                        Code:    rpc.CodePrecondition,
                        Message: "git not found on this node — install git for push-to-deploy (ADR-0019)",
                }
        }
        return bin, nil
}

// releasesRoot returns <home>/.nexus-git/<domain>/releases (created).
func releasesRoot(homeRoot, username, domain string) (string, error) {
        if !wafFqdnRe.MatchString(domain) {
                return "", fmt.Errorf("invalid domain")
        }
        home, err := fsTarget(homeRoot, username, ".")
        if err != nil {
                return "", err
        }
        root := filepath.Join(home, gitReleasesDir, domain, "releases")
        if err := os.MkdirAll(root, 0o755); err != nil {
                return "", err
        }
        _, _ = chownToUserBestEffort(filepath.Dir(filepath.Dir(root)), username)
        return root, nil
}

// gitDeploy clones/checks out the repo into a new release and atomically
// swaps the deploy-path symlink.
func (r *Registry) gitDeploy(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
        dec := json.NewDecoder(strings.NewReader(string(raw)))
        dec.DisallowUnknownFields()
        var p gitDeployParams
        if err := dec.Decode(&p); err != nil {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid params: " + err.Error()}
        }
        if !gitRepoRe.MatchString(p.RepoURL) {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "repo_url must be an https or ssh git URL"}
        }
        if p.Branch == "" {
                p.Branch = "main"
        }
        if !gitBranchRe.MatchString(p.Branch) {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid branch"}
        }
        if p.Sha != "" && !gitShaRe.MatchString(p.Sha) {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid sha"}
        }
        deployPath, err := resolveAccountPath(r.deps.HomeRoot, p.Username, p.DeployPath)
        if err != nil {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: err.Error()}
        }
        root, err := releasesRoot(r.deps.HomeRoot, p.Username, p.Domain)
        if err != nil {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: err.Error()}
        }

        // The deploy path must be absent or a symlink — never a real directory.
        if fi, err := os.Lstat(deployPath); err == nil {
                if fi.Mode()&os.ModeSymlink == 0 {
                        return nil, nil, &rpc.RPCError{
                                Code:    rpc.CodeConflict,
                                Message: "deploy path exists and is a real directory — the deploy model replaces it with a release symlink; choose a fresh path or move the content away",
                        }
                }
        }

        bin, err := r.gitBinary()
        if err != nil {
                return nil, nil, err
        }
        sha := p.Sha
        if sha == "" {
                sha = p.Branch // checkout by branch when no sha pinned
        }
        env := append(os.Environ(), "GIT_TERMINAL_PROMPT=0")
        var log strings.Builder

        // 1. clone into a staging dir, resolve the deployed sha, then rename to
        // the final release id — release names are always <ts>-<sha7> (+ -N for
        // same-second deploys), which makes the history view honest.
        tmpDir, terr := os.MkdirTemp(root, ".tmp-")
        if terr != nil {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: "staging dir failed: " + terr.Error()}
        }
        clone := exec.Command(bin, "clone", "--branch", p.Branch, p.RepoURL, tmpDir)
        clone.Env = env
        cloneOut, err := clone.CombinedOutput()
        log.WriteString(string(cloneOut))
        if err != nil {
                _ = os.RemoveAll(tmpDir)
                return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "git clone failed: " + firstLine(string(cloneOut))}
        }
        // 2. pin the exact sha when one was pushed.
        if p.Sha != "" {
                checkout := exec.Command(bin, "-C", tmpDir, "checkout", "--detach", p.Sha)
                checkout.Env = env
                coOut, cerr := checkout.CombinedOutput()
                log.WriteString(string(coOut))
                if cerr != nil {
                        _ = os.RemoveAll(tmpDir)
                        return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "git checkout failed: " + firstLine(string(coOut))}
                }
        }
        head := exec.Command(bin, "-C", tmpDir, "rev-parse", "HEAD")
        head.Env = env
        headOut, herr := head.Output()
        deployedSha := strings.TrimSpace(string(headOut))
        if herr != nil || deployedSha == "" {
                deployedSha = sha
        }
        base := fmt.Sprintf("%d-%s", time.Now().Unix(), shortSha(deployedSha))
        releaseID := base
        for i := 2; ; i++ {
                if _, statErr := os.Stat(filepath.Join(root, releaseID)); os.IsNotExist(statErr) {
                        break
                }
                releaseID = fmt.Sprintf("%s-%d", base, i)
        }
        releaseDir := filepath.Join(root, releaseID)
        if rerr := os.Rename(tmpDir, releaseDir); rerr != nil {
                _ = os.RemoveAll(tmpDir)
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: "release rename failed: " + rerr.Error()}
        }
        log.WriteString("deployed " + deployedSha + "\n")
        _ = os.WriteFile(filepath.Join(releaseDir, ".nexus-deploy.log"), []byte(log.String()), 0o644)
        _, _ = chownToUserBestEffort(releaseDir, p.Username)

        // 3. atomic symlink swap.
        tmp := deployPath + ".nexus-swap"
        _ = os.Remove(tmp)
        if err := os.Symlink(releaseDir, tmp); err != nil {
                _ = os.RemoveAll(releaseDir)
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: "symlink stage failed: " + err.Error()}
        }
        if err := os.Rename(tmp, deployPath); err != nil {
                _ = os.Remove(tmp)
                _ = os.RemoveAll(releaseDir)
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: "symlink swap failed: " + err.Error()}
        }
        _, _ = chownToUserBestEffort(deployPath, p.Username)

        entry := r.deps.WAL.NewEntry("git.deploy", map[string]any{
                "username": p.Username, "domain": p.Domain, "repo": p.RepoURL,
                "branch": p.Branch, "sha": deployedSha, "release": releaseID,
        })
        _ = r.deps.WAL.Append(entry)
        return gitDeployResult{
                Status:    "deployed",
                ReleaseID: releaseID,
                Sha:       deployedSha,
                Path:      deployPath,
                Log:       log.String(),
        }, auditQueued(entry), nil
}

// gitDeployHistory lists the releases (read-only, spec §6).
func (r *Registry) gitDeployHistory(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
        var p struct {
                Username   string `json:"username"`
                Domain     string `json:"domain"`
                DeployPath string `json:"deploy_path"`
        }
        if err := decodeParams(raw, &p); err != nil {
                return nil, nil, err
        }
        deployPath, err := resolveAccountPath(r.deps.HomeRoot, p.Username, p.DeployPath)
        if err != nil {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: err.Error()}
        }
        root, err := releasesRoot(r.deps.HomeRoot, p.Username, p.Domain)
        if err != nil {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: err.Error()}
        }
        entries, _ := os.ReadDir(root)
        res := gitHistoryResult{Releases: []gitRelease{}, Path: deployPath}
        if target, err := os.Readlink(deployPath); err == nil {
                res.Current = filepath.Base(target)
        }
        for _, e := range entries {
                m := releaseRe.FindStringSubmatch(e.Name())
                if m == nil {
                        continue
                }
                ts, _ := strconv.ParseInt(m[1], 10, 64)
                res.Releases = append(res.Releases, gitRelease{
                        ReleaseID: e.Name(),
                        Sha:       m[2],
                        CreatedAt: time.Unix(ts, 0).UTC().Format("2006-01-02T15:04:05Z"),
                        Active:    e.Name() == res.Current,
                })
        }
        sort.Slice(res.Releases, func(i, j int) bool { return res.Releases[i].ReleaseID > res.Releases[j].ReleaseID })
        return res, nil, nil
}

// gitRollback re-points the deploy symlink to an older release (audited).
func (r *Registry) gitRollback(id string, raw json.RawMessage) (any, *rpc.AuditHint, error) {
        var p struct {
                Username   string `json:"username"`
                Domain     string `json:"domain"`
                DeployPath string `json:"deploy_path"`
                ReleaseID  string `json:"release_id"`
        }
        if err := decodeParams(raw, &p); err != nil {
                return nil, nil, err
        }
        if !releaseRe.MatchString(p.ReleaseID) {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: "invalid release id"}
        }
        deployPath, err := resolveAccountPath(r.deps.HomeRoot, p.Username, p.DeployPath)
        if err != nil {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: err.Error()}
        }
        root, err := releasesRoot(r.deps.HomeRoot, p.Username, p.Domain)
        if err != nil {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInvalidParams, Message: err.Error()}
        }
        releaseDir := filepath.Join(root, p.ReleaseID)
        if fi, err := os.Stat(releaseDir); err != nil || !fi.IsDir() {
                return nil, nil, &rpc.RPCError{Code: rpc.CodePrecondition, Message: "release not found"}
        }
        tmp := deployPath + ".nexus-swap"
        _ = os.Remove(tmp)
        if err := os.Symlink(releaseDir, tmp); err != nil {
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: "symlink stage failed: " + err.Error()}
        }
        if err := os.Rename(tmp, deployPath); err != nil {
                _ = os.Remove(tmp)
                return nil, nil, &rpc.RPCError{Code: rpc.CodeInternalError, Message: "symlink swap failed: " + err.Error()}
        }
        entry := r.deps.WAL.NewEntry("git.rollback", map[string]any{
                "username": p.Username, "domain": p.Domain, "release": p.ReleaseID,
        })
        _ = r.deps.WAL.Append(entry)
        return map[string]any{"status": "rolled_back", "release_id": p.ReleaseID}, auditQueued(entry), nil
}

func shortSha(sha string) string {
        if len(sha) > 7 {
                return sha[:7]
        }
        return sha
}
