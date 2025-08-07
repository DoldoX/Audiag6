package main

// API request/response types for scanning and diagnostics evidence.

type ScanRequest struct {
	Seeds        []string `json:"seeds"`
	SNMPVersion  string   `json:"snmpVersion"` // "v2c" or "v3"
	Community    string   `json:"community,omitempty"`
	V3User       string   `json:"v3user,omitempty"`
	V3AuthProto  string   `json:"v3authproto,omitempty"`
	V3AuthPass   string   `json:"v3authpass,omitempty"`
	V3PrivProto  string   `json:"v3privproto,omitempty"`
	V3PrivPass   string   `json:"v3privpass,omitempty"`
	FDBThreshold int      `json:"fdbThreshold,omitempty"` // minimalna liczba wspólnych MAC dla połączenia (domyślnie 3)
	CDPDebug     bool     `json:"cdpDebug,omitempty"`     // gdy true: dołącz surowy zrzut OID->value CDP do diagnostics.raw.cdp
}

// Evidence structures exposed in API

type EdgeEndpoint struct {
	Device string `json:"device,omitempty"`
	If     string `json:"if,omitempty"`
}

type EdgeEvidence struct {
	Source     string       `json:"source,omitempty"`     // lldp/cdp/fdb
	Confidence string       `json:"confidence,omitempty"` // high/medium/low
	A          EdgeEndpoint `json:"a,omitempty"`
	B          EdgeEndpoint `json:"b,omitempty"`
	VLAN       *int         `json:"vlan,omitempty"`
	SharedMacs int          `json:"sharedMacs,omitempty"`
	SampleMacs []string     `json:"sampleMacs,omitempty"` // <= 5
	UsedOids   []string     `json:"usedOids,omitempty"`
}

type DeviceEvidence struct {
	LldpLocalCount  int      `json:"lldpLocalCount,omitempty"`
	LldpRemoteCount int      `json:"lldpRemoteCount,omitempty"`
	MgmtIPs         []string `json:"mgmtIPs,omitempty"`
	FdbTotalEntries int      `json:"fdbTotalEntries,omitempty"`
	VlanCount       int      `json:"vlanCount,omitempty"`
	OidErrors       []string `json:"oidErrors,omitempty"`
}

type Diagnostics struct {
	Stats struct {
		Nodes  int      `json:"nodes"`
		Edges  int      `json:"edges"`
		Source []string `json:"source,omitempty"`
	} `json:"stats"`
	Devices map[string]DeviceEvidence `json:"devices,omitempty"` // key: device ID
	Edges   map[string]EdgeEvidence   `json:"edges,omitempty"`   // key: edge ID
	Raw     map[string]interface{}    `json:"raw,omitempty"`     // dodatkowe surowe dane debug (np. raw.cdp)
}

type TopologyNode struct {
	Id     string                 `json:"id"`
	Label  string                 `json:"label"`
	Role   string                 `json:"role,omitempty"`
	Vendor string                 `json:"vendor,omitempty"`
	Data   map[string]interface{} `json:"data,omitempty"`
	// Optional evidence attached to node (per-device)
	Evidence *DeviceEvidence `json:"evidence,omitempty"`
}

type TopologyEdge struct {
	Id     string                 `json:"id"`
	Source string                 `json:"source"`
	Target string                 `json:"target"`
	Type   string                 `json:"type,omitempty"`  // trunk/access/lag
	Label  string                 `json:"label,omitempty"`
	Score  string                 `json:"score,omitempty"` // high/medium/low
	Data   map[string]interface{} `json:"data,omitempty"`
	// Evidence for this edge (source/confidence/ports/VLAN/MACs/OIDs)
	Evidence *EdgeEvidence `json:"evidence,omitempty"`
}

type TopologyPayload struct {
	Nodes []TopologyNode `json:"nodes"`
	Edges []TopologyEdge `json:"edges"`
}

type ScanResponse struct {
	Status      string           `json:"status"`
	Topology    TopologyPayload  `json:"topology,omitempty"`
	Diagnostics Diagnostics      `json:"diagnostics,omitempty"`
	Error       string           `json:"error,omitempty"`
}
