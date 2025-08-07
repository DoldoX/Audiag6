package graph

// Core data model for MVP (L2 focus) with evidence fields.

type Device struct {
	ID         string            `json:"id"`
	Name       string            `json:"name"`
	Vendor     string            `json:"vendor,omitempty"`
	Role       string            `json:"role,omitempty"` // core/distribution/access/unknown
	SysDescr   string            `json:"sysDescr,omitempty"`
	Meta       map[string]string `json:"meta,omitempty"`
	Interfaces []Interface       `json:"interfaces,omitempty"`

	// Evidence (per-device) – collected in backend; may be forwarded via pipeline
	Evidence *DeviceEvidence `json:"evidence,omitempty"`
}

type Interface struct {
	DeviceID string            `json:"deviceId"`
	Name     string            `json:"name"`
	Index    int               `json:"index,omitempty"`
	Descr    string            `json:"descr,omitempty"`
	Speed    int64             `json:"speedbps,omitempty"`
	AdminUp  bool              `json:"adminUp,omitempty"`
	OperUp   bool              `json:"operUp,omitempty"`
	Trunk    bool              `json:"trunk,omitempty"`
	VLANs    []int             `json:"vlans,omitempty"`
	Meta     map[string]string `json:"meta,omitempty"`
}

type Link struct {
	ID        string            `json:"id"`
	ADeviceID string            `json:"aDeviceId"`
	AIfName   string            `json:"aIfName"`
	BDeviceID string            `json:"bDeviceId"`
	BIfName   string            `json:"bIfName"`
	Type      string            `json:"type,omitempty"`  // trunk/access/lag/unknown
	Label     string            `json:"label,omitempty"` // free-form (e.g., "Gi1/0/1 - 10,20")
	Score     string            `json:"score,omitempty"` // high/medium/low
	Meta      map[string]string `json:"meta,omitempty"`

	// Evidence (per-edge): source/confidence/ports/VLAN/shared MACs/OIDs
	Evidence *EdgeEvidence `json:"evidence,omitempty"`
}

type Topology struct {
	Devices []Device `json:"nodes"`
	Links   []Link   `json:"edges"`
	// Optional raw debug dumps (e.g., OID→value) keyed by subsystem name (e.g., "cdp")
	Raw map[string]map[string]string `json:"raw,omitempty"`
}

// Evidence types in internal model (mirror API-level semantics)

type EdgeEndpoint struct {
	Device string `json:"device,omitempty"`
	If     string `json:"if,omitempty"`
}

type EdgeEvidence struct {
	Source     string   `json:"source,omitempty"`     // lldp/cdp/fdb
	Confidence string   `json:"confidence,omitempty"` // high/medium/low
	A          EdgeEndpoint `json:"a,omitempty"`
	B          EdgeEndpoint `json:"b,omitempty"`
	VLAN       *int     `json:"vlan,omitempty"`
	SharedMacs int      `json:"sharedMacs,omitempty"`
	SampleMacs []string `json:"sampleMacs,omitempty"` // <= 5
	UsedOids   []string `json:"usedOids,omitempty"`
}

type DeviceEvidence struct {
	LldpLocalCount  int      `json:"lldpLocalCount,omitempty"`
	LldpRemoteCount int      `json:"lldpRemoteCount,omitempty"`
	MgmtIPs         []string `json:"mgmtIPs,omitempty"`
	FdbTotalEntries int      `json:"fdbTotalEntries,omitempty"`
	VlanCount       int      `json:"vlanCount,omitempty"`
	OidErrors       []string `json:"oidErrors,omitempty"`
}
