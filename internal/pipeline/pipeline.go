package pipeline

// Minimal pipeline wiring: accepts a collector, seeds, and produces a UI-friendly
// topology format (nodes/edges) that matches the current web client expectations.

import (
	"context"
	"fmt"

	sn "audiatopology/internal/collectors/snmp"
	g "audiatopology/internal/graph"
)

type UINode struct {
	Id     string            `json:"id"`
	Label  string            `json:"label"`
	Role   string            `json:"role,omitempty"`
	Vendor string            `json:"vendor,omitempty"`
	Data   map[string]string `json:"data,omitempty"`
	// Optional per-device evidence (backend-populated)
	// Mirrors graph.DeviceEvidence (kept as raw map for forward/backward compatibility)
	Evidence map[string]interface{} `json:"evidence,omitempty"`
}

type UIEdge struct {
	Id     string            `json:"id"`
	Source string            `json:"source"`
	Target string            `json:"target"`
	Type   string            `json:"type,omitempty"` // trunk/access/lag
	Label  string            `json:"label,omitempty"`
	Score  string            `json:"score,omitempty"` // high/medium/low
	Data   map[string]string `json:"data,omitempty"`
	// Optional per-edge evidence (backend-populated)
	// Mirrors graph.EdgeEvidence (kept as raw map for forward/backward compatibility)
	Evidence map[string]interface{} `json:"evidence,omitempty"`
}

type UITopology struct {
	Nodes []UINode `json:"nodes"`
	Edges []UIEdge `json:"edges"`
	// Optional raw debug data forwarded from collectors (e.g., "cdp": OID->value)
	Raw map[string]map[string]string `json:"raw,omitempty"`
}

type Seeds struct {
	Targets []sn.Target `json:"targets"`
}

type Collector interface {
	Discover(ctx context.Context, targets []sn.Target) (g.Topology, error)
}

// Run executes discovery and converts the internal graph to the UI format.
func Run(ctx context.Context, c Collector, seeds Seeds) (UITopology, error) {
	top, err := c.Discover(ctx, seeds.Targets)
	if err != nil {
		return UITopology{}, err
	}

	var ui UITopology
	// forward raw debug dumps if present
	if top.Raw != nil {
		ui.Raw = top.Raw
	}
	for _, d := range top.Devices {
		n := UINode{
			Id:     d.ID,
			Label:  coalesce(d.Name, d.ID),
			Role:   coalesce(d.Role, "unknown"),
			Vendor: d.Vendor,
			Data:   map[string]string{},
		}
		// propagate evidence if present
		if d.Evidence != nil {
			n.Evidence = map[string]interface{}{
				"lldpLocalCount":  d.Evidence.LldpLocalCount,
				"lldpRemoteCount": d.Evidence.LldpRemoteCount,
				"mgmtIPs":         d.Evidence.MgmtIPs,
				"fdbTotalEntries": d.Evidence.FdbTotalEntries,
				"vlanCount":       d.Evidence.VlanCount,
				"oidErrors":       d.Evidence.OidErrors,
			}
		}
		ui.Nodes = append(ui.Nodes, n)
	}
	for _, l := range top.Links {
		id := l.ID
		if id == "" {
			id = fmt.Sprintf("%s:%s-%s:%s", l.ADeviceID, l.AIfName, l.BDeviceID, l.BIfName)
		}
		lbl := l.Label
		if lbl == "" && (l.AIfName != "" || l.BIfName != "") {
			if l.AIfName != "" && l.BIfName != "" {
				lbl = fmt.Sprintf("%s ↔ %s", l.AIfName, l.BIfName)
			} else {
				lbl = l.AIfName + l.BIfName
			}
		}
		e := UIEdge{
			Id:     id,
			Source: l.ADeviceID,
			Target: l.BDeviceID,
			Type:   coalesce(l.Type, "link"),
			Label:  lbl,
			Score:  coalesce(l.Score, "low"),
			Data:   map[string]string{},
		}
		// propagate edge evidence if present
		if l.Evidence != nil {
			ev := map[string]interface{}{
				"source":     l.Evidence.Source,
				"confidence": l.Evidence.Confidence,
				"a": map[string]interface{}{
					"device": l.Evidence.A.Device,
					"if":     l.Evidence.A.If,
				},
				"b": map[string]interface{}{
					"device": l.Evidence.B.Device,
					"if":     l.Evidence.B.If,
				},
				"sharedMacs": l.Evidence.SharedMacs,
				"sampleMacs": l.Evidence.SampleMacs,
				"usedOids":   l.Evidence.UsedOids,
			}
			if l.Evidence.VLAN != nil {
				ev["vlan"] = *l.Evidence.VLAN
			}
			e.Evidence = ev
		} else {
			// Ensure edges without explicit evidence still carry minimal A/B info for diagnostics
			if l.ADeviceID != "" || l.BDeviceID != "" || l.AIfName != "" || l.BIfName != "" {
				e.Evidence = map[string]interface{}{
					"source":     coalesce(l.Score, "low"), // fallback: use score as weak source hint
					"confidence": coalesce(l.Score, "low"),
					"a": map[string]interface{}{
						"device": l.ADeviceID,
						"if":     l.AIfName,
					},
					"b": map[string]interface{}{
						"device": l.BDeviceID,
						"if":     l.BIfName,
					},
				}
			}
		}
		ui.Edges = append(ui.Edges, e)
	}
	return ui, nil
}

func coalesce[T ~string](v T, def T) T {
	if v == "" {
		return def
	}
	return v
}
