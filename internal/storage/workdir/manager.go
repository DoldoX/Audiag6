package workdir

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type Manager struct {
	path string
	// user config location (per-profile), stores last chosen workdir
	cfgPath string
}
 
 // Project state persisted in workdir/project/project.json
 type Project struct {
 	UpdatedAt time.Time       `json:"updatedAt"`
 	Stats     ProjectStats    `json:"stats"`
 	Devices   []ProjectDevice `json:"devices"`
 	Edges     []ProjectEdge   `json:"edges"`
 }
 
 type ProjectStats struct {
 	Devices int      `json:"devices"`
 	Edges   int      `json:"edges"`
 	Sources []string `json:"sources,omitempty"`
 }
 
 type ProjectDevice struct {
 	ID            string            `json:"id"`            // deviceId (sysName lub mgmtIP)
 	SysName       string            `json:"sysName,omitempty"`
 	MgmtIPs       []string          `json:"mgmtIPs,omitempty"`
 	Vendor        string            `json:"vendor,omitempty"`
 	IfMap         map[string]string `json:"ifMap,omitempty"` // ifIndex -> ifName
 	LLDPLocal     int               `json:"lldpLocalCount,omitempty"`
 	LLDPRemote    int               `json:"lldpRemoteCount,omitempty"`
 	FDBTotal      int               `json:"fdbTotalEntries,omitempty"`
 	VLANs         []int             `json:"vlans,omitempty"`
 	LastSeen      time.Time         `json:"lastSeen"`
 	SeenCount     int               `json:"seenCount"`
 }
 
 type ProjectEdge struct {
 	ID         string    `json:"id"` // (a:if)-(b:if)-source posortowane
 	ADeviceID  string    `json:"aDeviceId"`
 	AIf        string    `json:"aIf"`
 	BDeviceID  string    `json:"bDeviceId"`
 	BIf        string    `json:"bIf"`
 	Source     string    `json:"source"`                 // lldp|fdb|cdp
 	Confidence string    `json:"confidence,omitempty"`   // high|medium|low
 	VLAN       *int      `json:"vlan,omitempty"`
 	SharedMacs int       `json:"sharedMacs,omitempty"`
 	SampleMacs []string  `json:"sampleMacs,omitempty"`   // <=5
 	UsedOids   []string  `json:"usedOids,omitempty"`
 	LastSeen   time.Time `json:"lastSeen"`
 	SeenCount  int       `json:"seenCount"`
 }

// NewManager resolves initial workdir using priority:
// 1) ENV AUDITOP_WORKDIR
// 2) user config.json (stored under %LOCALAPPDATA%/AuditTopology/config.json on Windows)
// 3) default OS path: %LOCALAPPDATA%/AuditTopology/workspace (Windows), $HOME/.local/share/AuditTopology/workspace (Linux), ~/Library/Application Support/AuditTopology/workspace (macOS)
func NewManager() *Manager {
	m := &Manager{}
	m.cfgPath = userConfigPath()
	m.path = resolveInitialPath(m.cfgPath)
	return m
}

func (m *Manager) Path() string {
	return m.path
}

// SetPath updates the path and persists it in user config.json (not in app tree).
func (m *Manager) SetPath(p string) error {
	p = strings.TrimSpace(p)
	if p == "" {
		return errors.New("empty path")
	}
	abs, err := filepath.Abs(p)
	if err != nil {
		return err
	}
	m.path = abs
	// persist
	if err := ensureDir(filepath.Dir(m.cfgPath)); err != nil {
		return err
	}
	cfg := map[string]string{"workdir": m.path}
	b, _ := json.MarshalIndent(cfg, "", "  ")
	return os.WriteFile(m.cfgPath, b, 0o600)
}

// EnsureStructure makes sure required subdirs exist:
// scans/YYYY-MM-DD_hhmmss_{hash}/, cache/, artifacts/, and root exists.
func (m *Manager) EnsureStructure() error {
	if m.path == "" {
		return errors.New("workdir not set")
	}
	// root
	if err := ensureDir(m.path); err != nil {
		return err
	}
	// cache, artifacts, scans, project
	for _, d := range []string{"cache", "artifacts", "scans", "project"} {
		if err := ensureDir(filepath.Join(m.path, d)); err != nil {
			return err
		}
	}
	// config.json (user-level settings) live under user profile (m.cfgPath), not inside workdir
	return nil
}

type ScanSession struct {
	Path string
}

// NewScanSession creates a timestamped folder under workdir/scans and returns the session handle.
func (m *Manager) NewScanSession() (ScanSession, error) {
	base := filepath.Join(m.path, "scans")
	if err := ensureDir(base); err != nil {
		return ScanSession{}, err
	}
	ts := time.Now().Format("2006-01-02_150405")
	dir := filepath.Join(base, fmt.Sprintf("%s", ts))
	if err := ensureDir(dir); err != nil {
		return ScanSession{}, err
	}
return ScanSession{Path: dir}, nil
}

 // Project helpers (load/save/merge)
 
 func (m *Manager) projectFilePath() string {
 	return filepath.Join(m.path, "project", "project.json")
 }
 
 func (m *Manager) LoadProject() (Project, error) {
 	var p Project
 	fp := m.projectFilePath()
 	b, err := os.ReadFile(fp)
 	if err != nil {
 		if os.IsNotExist(err) {
 			return Project{}, nil
 		}
 		return Project{}, err
 	}
 	if err := json.Unmarshal(b, &p); err != nil {
 		return Project{}, err
 	}
 	return p, nil
 }
 
 func (m *Manager) SaveProject(p Project) error {
 	if err := ensureDir(filepath.Dir(m.projectFilePath())); err != nil {
 		return err
 	}
 	b, err := json.MarshalIndent(p, "", "  ")
 	if err != nil {
 		return err
 	}
 	return os.WriteFile(m.projectFilePath(), b, 0o600)
 }
 
 // MergeProject merges new scan results (topology + diagnostics-like stats) into project state.
 // topo: expects structure similar to cmd/auditopology/api_types.TopologyPayload (Nodes/Edges with Evidence fields).
 func (m *Manager) MergeProject(topo any, diag any, now time.Time) error {
 	// We accept 'any' to avoid import cycles; decode via json roundtrip into lightweight structs.
 	// Define minimal views:
 	type nodeView struct {
 		Id       string                 `json:"id"`
 		Label    string                 `json:"label,omitempty"`
 		Vendor   string                 `json:"vendor,omitempty"`
 		Data     map[string]interface{} `json:"data,omitempty"`
 		Evidence *struct {
 			LldpLocalCount  int      `json:"lldpLocalCount,omitempty"`
 			LldpRemoteCount int      `json:"lldpRemoteCount,omitempty"`
 			MgmtIPs         []string `json:"mgmtIPs,omitempty"`
 			FdbTotalEntries int      `json:"fdbTotalEntries,omitempty"`
 			VlanCount       int      `json:"vlanCount,omitempty"`
 		} `json:"evidence,omitempty"`
 	}
 	type edgeView struct {
 		Id       string                 `json:"id"`
 		Data     map[string]interface{} `json:"data,omitempty"`
 		Evidence *struct {
 			Source     string   `json:"source,omitempty"`
 			Confidence string   `json:"confidence,omitempty"`
 			A          struct {
 				Device string `json:"device,omitempty"`
 				If     string `json:"if,omitempty"`
 			} `json:"a,omitempty"`
 			B struct {
 				Device string `json:"device,omitempty"`
 				If     string `json:"if,omitempty"`
 			} `json:"b,omitempty"`
 			VLAN       *int     `json:"vlan,omitempty"`
 			SharedMacs int      `json:"sharedMacs,omitempty"`
 			SampleMacs []string `json:"sampleMacs,omitempty"`
 			UsedOids   []string `json:"usedOids,omitempty"`
 		} `json:"evidence,omitempty"`
 	}
 	type topoView struct {
 		Nodes []nodeView `json:"nodes"`
 		Edges []edgeView `json:"edges"`
 	}
 
 	var tv topoView
 	// json roundtrip to map topo into topoView
 	b, err := json.Marshal(topo)
 	if err != nil {
 		return err
 	}
 	if err := json.Unmarshal(b, &tv); err != nil {
 		return err
 	}
 
 	// Load existing project
 	p, err := m.LoadProject()
 	if err != nil {
 		return err
 	}
 
 	// Build indexes
 	devIdx := map[string]int{}
 	for i, d := range p.Devices {
 		devIdx[d.ID] = i
 	}
 	edgeIdx := map[string]int{}
 	for i, e := range p.Edges {
 		edgeIdx[e.ID] = i
 	}
 
 	// Helper to pick deviceId: prefer sysName, else first mgmtIP, else node.Id
 	pickDevID := func(n nodeView) string {
 		if n.Label != "" {
 			// Label may hold sysName in UI; but safer is evidence.MgmtIPs/sysName if available
 		}
 		if n.Evidence != nil && len(n.Evidence.MgmtIPs) > 0 {
 			return n.Id // keep stable with backend ids; we still store mgmtIPs
 		}
 		return n.Id
 	}
 
 	// Upsert devices
 	for _, n := range tv.Nodes {
 		id := pickDevID(n)
 		d := ProjectDevice{
 			ID:        id,
 			SysName:   n.Label,
 			Vendor:    n.Vendor,
 			LastSeen:  now,
 			SeenCount: 1,
 		}
 		if n.Evidence != nil {
 			d.LLDPLocal = n.Evidence.LldpLocalCount
 			d.LLDPRemote = n.Evidence.LldpRemoteCount
 			d.MgmtIPs = append(d.MgmtIPs, n.Evidence.MgmtIPs...)
 			d.FDBTotal = n.Evidence.FdbTotalEntries
 			// VLANs: from count only; no specific ids here
 		}
 		if i, ok := devIdx[id]; ok {
 			// merge
 			ex := p.Devices[i]
 			if d.SysName != "" {
 				ex.SysName = d.SysName
 			}
 			if d.Vendor != "" {
 				ex.Vendor = d.Vendor
 			}
 			if len(d.MgmtIPs) > 0 {
 				ex.MgmtIPs = unionStrings(ex.MgmtIPs, d.MgmtIPs)
 			}
 			if d.LLDPLocal > 0 {
 				ex.LLDPLocal = d.LLDPLocal
 			}
 			if d.LLDPRemote > 0 {
 				ex.LLDPRemote = d.LLDPRemote
 			}
 			if d.FDBTotal > ex.FDBTotal {
 				ex.FDBTotal = d.FDBTotal
 			}
 			ex.LastSeen = now
 			ex.SeenCount++
 			p.Devices[i] = ex
 		} else {
 			p.Devices = append(p.Devices, d)
 			devIdx[id] = len(p.Devices) - 1
 		}
 	}
 
 	// Upsert edges
 	for _, e := range tv.Edges {
 		if e.Evidence == nil {
 			continue
 		}
 		aDev := strings.TrimSpace(e.Evidence.A.Device)
 		bDev := strings.TrimSpace(e.Evidence.B.Device)
 		aIf := strings.TrimSpace(e.Evidence.A.If)
 		bIf := strings.TrimSpace(e.Evidence.B.If)
 		src := strings.TrimSpace(e.Evidence.Source)
 		if aDev == "" || bDev == "" || aIf == "" || bIf == "" || src == "" {
 			// cannot build stable edge id
 			continue
 		}
 		// normalized order
 		left := fmt.Sprintf("%s:%s", aDev, aIf)
 		right := fmt.Sprintf("%s:%s", bDev, bIf)
 		if right < left {
 			left, right = right, left
 		}
 		id := fmt.Sprintf("%s-%s-%s", left, right, src)
 
 		pe := ProjectEdge{
 			ID:         id,
 			ADeviceID:  aDev,
 			AIf:        aIf,
 			BDeviceID:  bDev,
 			BIf:        bIf,
 			Source:     src,
 			Confidence: e.Evidence.Confidence,
 			VLAN:       e.Evidence.VLAN,
 			SharedMacs: e.Evidence.SharedMacs,
 			SampleMacs: e.Evidence.SampleMacs,
 			UsedOids:   e.Evidence.UsedOids,
 			LastSeen:   now,
 			SeenCount:  1,
 		}
 		if i, ok := edgeIdx[id]; ok {
 			ex := p.Edges[i]
 			// update confidence if stronger, else keep
 			ex.Confidence = strongerConfidence(ex.Confidence, pe.Confidence)
 			// keep vlan if present
 			if pe.VLAN != nil {
 				ex.VLAN = pe.VLAN
 			}
 			if pe.SharedMacs > ex.SharedMacs {
 				ex.SharedMacs = pe.SharedMacs
 			}
 			if len(pe.SampleMacs) > 0 {
 				ex.SampleMacs = unionStrings(ex.SampleMacs, pe.SampleMacs)
 			}
 			if len(pe.UsedOids) > 0 {
 				ex.UsedOids = unionStrings(ex.UsedOids, pe.UsedOids)
 			}
 			ex.LastSeen = now
 			ex.SeenCount++
 			p.Edges[i] = ex
 		} else {
 			p.Edges = append(p.Edges, pe)
 			edgeIdx[id] = len(p.Edges) - 1
 		}
 	}
 
 	// Update stats
 	p.UpdatedAt = now
 	p.Stats.Devices = len(p.Devices)
 	p.Stats.Edges = len(p.Edges)
 	p.Stats.Sources = []string{"lldp", "fdb", "cdp"}
 
 	return m.SaveProject(p)
 }
 
 func unionStrings(a, b []string) []string {
 	m := map[string]struct{}{}
 	for _, v := range a {
 		m[v] = struct{}{}
 	}
 	for _, v := range b {
 		m[v] = struct{}{}
 	}
 	out := make([]string, 0, len(m))
 	for v := range m {
 		out = append(out, v)
 	}
 	return out
 }
 
 func strongerConfidence(old, new string) string {
 	score := func(s string) int {
 		switch strings.ToLower(s) {
 		case "high":
 			return 3
 		case "medium":
 			return 2
 		case "low":
 			return 1
 		default:
 			return 0
 		}
 	}
 	if score(new) >= score(old) {
 		return new
 	}
 	return old
 }

// SaveJSON writes any payload as pretty JSON into given filename inside session folder.
func (m *Manager) SaveJSON(sess ScanSession, filename string, v any) error {
	if strings.TrimSpace(sess.Path) == "" {
		return errors.New("empty session path")
	}
	if err := ensureDir(sess.Path); err != nil {
		return err
	}
	full := filepath.Join(sess.Path, filename)
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(full, b, 0o600)
}

// Helpers

func ensureDir(p string) error {
	return os.MkdirAll(p, 0o755)
}

func userConfigPath() string {
	// Windows: %LOCALAPPDATA%\AuditTopology\config.json
	if v := os.Getenv("LOCALAPPDATA"); v != "" {
		return filepath.Join(v, "AuditTopology", "config.json")
	}
	// Linux: ~/.local/share/AuditTopology/config.json
	home, _ := os.UserHomeDir()
	if home == "" {
		home = "."
	}
	if isWindows() {
		// fallback if LOCALAPPDATA missing
		return filepath.Join(home, "AppData", "Local", "AuditTopology", "config.json")
	}
	if isMac() {
		return filepath.Join(home, "Library", "Application Support", "AuditTopology", "config.json")
	}
	// default Linux
	return filepath.Join(home, ".local", "share", "AuditTopology", "config.json")
}

func resolveInitialPath(cfg string) string {
	// Priority: ENV
	if env := strings.TrimSpace(os.Getenv("AUDITOP_WORKDIR")); env != "" {
		abs, _ := filepath.Abs(env)
		return abs
	}
	// user config
	if b, err := os.ReadFile(cfg); err == nil {
		var m map[string]string
		if json.Unmarshal(b, &m) == nil {
			if w := strings.TrimSpace(m["workdir"]); w != "" {
				abs, _ := filepath.Abs(w)
				return abs
			}
		}
	}
	// default OS path
	if v := os.Getenv("LOCALAPPDATA"); v != "" {
		return filepath.Join(v, "AuditTopology", "workspace")
	}
	home, _ := os.UserHomeDir()
	if home == "" {
		home = "."
	}
	if isMac() {
		return filepath.Join(home, "Library", "Application Support", "AuditTopology", "workspace")
	}
	if isWindows() {
		return filepath.Join(home, "AppData", "Local", "AuditTopology", "workspace")
	}
	return filepath.Join(home, ".local", "share", "AuditTopology", "workspace")
}

func isWindows() bool {
	return strings.Contains(strings.ToLower(os.Getenv("OS")), "windows")
}

func isMac() bool {
	// crude heuristic using GOOS not available directly; rely on env var
	// fallback by checking presence of typical mac env
	return strings.Contains(strings.ToLower(os.Getenv("TERM_PROGRAM")), "apple")
}
