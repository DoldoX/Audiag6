package main

import (
	g "audiatopology/internal/graph"
	"audiatopology/internal/pipeline"
)

// convertToUITopology converts internal graph.Topology to pipeline.UITopology
func convertToUITopology(topInterface interface{}) pipeline.UITopology {
	// Type assertion to get actual topology
	top, ok := topInterface.(g.Topology)
	if !ok {
		// Return empty topology if conversion fails
		return pipeline.UITopology{}
	}
	var ui pipeline.UITopology
	
	// Forward raw debug dumps if present
	if top.Raw != nil {
		ui.Raw = top.Raw
	}
	
	// Convert devices to UI nodes
	for _, d := range top.Devices {
		n := pipeline.UINode{
			Id:     d.ID,
			Label:  coalesce(d.Name, d.ID),
			Role:   coalesce(d.Role, "unknown"),
			Vendor: d.Vendor,
			Data:   map[string]string{},
		}
		// Propagate evidence if present
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
	
	// Convert links to UI edges
	for _, l := range top.Links {
		id := l.ID
		if id == "" {
			id = l.ADeviceID + ":" + l.AIfName + "-" + l.BDeviceID + ":" + l.BIfName
		}
		lbl := l.Label
		if lbl == "" && (l.AIfName != "" || l.BIfName != "") {
			if l.AIfName != "" && l.BIfName != "" {
				lbl = l.AIfName + " ↔ " + l.BIfName
			} else {
				lbl = l.AIfName + l.BIfName
			}
		}
		e := pipeline.UIEdge{
			Id:     id,
			Source: l.ADeviceID,
			Target: l.BDeviceID,
			Type:   coalesce(l.Type, "link"),
			Label:  lbl,
			Score:  coalesce(l.Score, "low"),
			Data:   map[string]string{},
		}
		// Propagate edge evidence if present
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
	return ui
}

func coalesce[T ~string](v T, def T) T {
	if v == "" {
		return def
	}
	return v
}