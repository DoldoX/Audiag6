package main

import (
	"context"
	"embed"
	"encoding/json"
	"io/fs"
	"log"
	"time"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"fmt"

	snmp "audiatopology/internal/collectors/snmp"
	"audiatopology/internal/pipeline"
	"audiatopology/internal/storage/workdir"
	"github.com/gosnmp/gosnmp"
)

/*
We embed the static UI from the path cmd/auditopology/web so that running `go run ./cmd/auditopology`
finds files reliably. We then strip the prefix when serving so URLs start at "/".
*/
//go:embed web/*
var webFS embed.FS

// Minimal backend serving a static UI (web/) and a sample topology JSON.
// This is a temporary bootstrap until the Tauri UI is wired. It allows quick preview.

type Node struct {
	Id     string            `json:"id"`
	Label  string            `json:"label"`
	Role   string            `json:"role,omitempty"`
	Vendor string            `json:"vendor,omitempty"`
	Data   map[string]string `json:"data,omitempty"`
}

type Edge struct {
	Id     string            `json:"id"`
	Source string            `json:"source"`
	Target string            `json:"target"`
	Type   string            `json:"type,omitempty"` // trunk/access/lag
	Label  string            `json:"label,omitempty"`
	Score  string            `json:"score,omitempty"` // high/medium/low
	Data   map[string]string `json:"data,omitempty"`
}

type Topology struct {
	Nodes []Node `json:"nodes"`
	Edges []Edge `json:"edges"`
}

// Helpers to convert pipeline.UITopology into API TopologyPayload
func convertNodes(in []pipeline.UINode) []TopologyNode {
	out := make([]TopologyNode, 0, len(in))
	for _, n := range in {
		out = append(out, TopologyNode{
			Id:     n.Id,
			Label:  n.Label,
			Role:   n.Role,
			Vendor: n.Vendor,
			Data:   map[string]interface{}(toAnyMap(n.Data)),
			// Evidence is backend-only for now; left nil
		})
	}
	return out
}

func convertEdges(in []pipeline.UIEdge) []TopologyEdge {
	out := make([]TopologyEdge, 0, len(in))
	for _, e := range in {
		out = append(out, TopologyEdge{
			Id:     e.Id,
			Source: e.Source,
			Target: e.Target,
			Type:   e.Type,
			Label:  e.Label,
			Score:  e.Score,
			Data:   map[string]interface{}(toAnyMap(e.Data)),
			// Evidence will be filled once collector provides it
		})
	}
	return out
}

func toAnyMap(m map[string]string) map[string]interface{} {
	if m == nil {
		return nil
	}
	out := make(map[string]interface{}, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func sampleTopology() Topology {
	return Topology{
		Nodes: []Node{
			{Id: "core1", Label: "CORE-1", Role: "core", Vendor: "cisco"},
			{Id: "dist1", Label: "DIST-1", Role: "distribution", Vendor: "aruba"},
			{Id: "dist2", Label: "DIST-2", Role: "distribution", Vendor: "juniper"},
			{Id: "acc1", Label: "ACC-1", Role: "access", Vendor: "mikrotik"},
			{Id: "acc2", Label: "ACC-2", Role: "access", Vendor: "hpe"},
		},
		Edges: []Edge{
			{Id: "e1", Source: "core1", Target: "dist1", Type: "trunk", Label: "Te1/1 - 10,20,30", Score: "high"},
			{Id: "e2", Source: "core1", Target: "dist2", Type: "trunk", Label: "Te1/2 - 10,20,30", Score: "high"},
			{Id: "e3", Source: "dist1", Target: "acc1", Type: "trunk", Label: "Gi1/0/1 - 10,20", Score: "medium"},
			{Id: "e4", Source: "dist2", Target: "acc2", Type: "access", Label: "Gi1/0/2 - 10", Score: "medium"},
		},
	}
}

func main() {
	mux := http.NewServeMux()

	// Workdir manager
	wdm := workdir.NewManager()
	if err := wdm.EnsureStructure(); err != nil {
		log.Printf("workdir ensure error: %v", err)
	}

	// API: topology generated via pipeline with NoOp SNMP collector (stub)
	mux.HandleFunc("/api/topology", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		collector := snmp.NewNoOp()
		seeds := pipeline.Seeds{
			Targets: []snmp.Target{
				{Address: "seed1.local", Credentials: snmp.Credentials{Version: "v2c", Community: "public"}},
			},
		}
		uiTop, err := pipeline.Run(context.Background(), collector, seeds)
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		// Wrap into new API TopologyPayload to match updated contract
		resp := ScanResponse{
			Status:   "ok",
			Topology: TopologyPayload{
				Nodes: convertNodes(uiTop.Nodes),
				Edges: convertEdges(uiTop.Edges),
			},
			// No Diagnostics in this endpoint
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(resp.Topology)
	})

	// API: GET/POST /api/workdir – odczyt/zmiana ścieżki roboczej
	mux.HandleFunc("/api/workdir", func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.Method {
		case http.MethodGet:
			_ = json.NewEncoder(w).Encode(map[string]string{"path": wdm.Path()})
			return
		case http.MethodPost:
			var body struct {
				Path string `json:"path"`
			}
			if err := json.NewDecoder(r.Body).Decode(&body); err != nil || strings.TrimSpace(body.Path) == "" {
				http.Error(w, "invalid JSON/path", http.StatusBadRequest)
				return
			}
			if err := wdm.SetPath(body.Path); err != nil {
				http.Error(w, err.Error(), http.StatusBadRequest)
				return
			}
			if err := wdm.EnsureStructure(); err != nil {
				http.Error(w, err.Error(), http.StatusInternalServerError)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]string{"path": wdm.Path()})
			return
		default:
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
	})
	// API: GET /api/project – bieżący stan projektu (project.json)
	mux.HandleFunc("/api/project", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		p, err := wdm.LoadProject()
		if err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(p)
	})

	// API: POST /api/scan – real SNMP (MVP: LLDP + IF basics) using gosnmp collector
	mux.HandleFunc("/api/scan", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		defer r.Body.Close()
		var req ScanRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}

		// Parametry dodatkowe (obecnie nieużywane bezpośrednio w collectorze; zachowane dla kompatybilności)
		// fdbThreshold := 3
		// if req.FDBThreshold > 0 {
		// 	fdbThreshold = req.FDBThreshold
		// }

		var targets []snmp.Target
		for _, s := range req.Seeds {
			s = strings.TrimSpace(s)
			if s == "" {
				continue
			}
			cred := snmp.Credentials{Version: req.SNMPVersion}
			if strings.ToLower(req.SNMPVersion) == "v3" {
				cred.V3 = &snmp.AuthV3{
					User: req.V3User,
					AuthPass: req.V3AuthPass,
					PrivPass: req.V3PrivPass,
				}
			} else {
				cred.Community = req.Community
			}
			targets = append(targets, snmp.Target{Address: s, Credentials: cred})
		}

		col := snmp.NewGoSNMP()

		// Uruchomienie pipeline jak wcześniej
		uiTop, err := pipeline.Run(context.Background(), col, pipeline.Seeds{Targets: targets})

		// Zbuduj Diagnostics zgodnie z nowym kontraktem
		var diag Diagnostics
		diag.Stats.Nodes = len(uiTop.Nodes)
		diag.Stats.Edges = len(uiTop.Edges)
		diag.Stats.Source = []string{"lldp", "fdb", "cdp"}
		diag.Devices = map[string]DeviceEvidence{} // zostaną uzupełnione po stronie UI na razie z topology.nodes[].evidence
		diag.Edges = map[string]EdgeEvidence{}     // zostaną uzupełnione po stronie UI na razie z topology.edges[].evidence
		diag.Raw = map[string]interface{}{}
		// jeśli collector dostarczył surowe zrzuty (uiTop.Raw), przenieś je do Diagnostics.Raw
		if uiTop.Raw != nil {
			if cdp, ok := uiTop.Raw["cdp"]; ok && cdp != nil {
				diag.Raw["cdp"] = cdp
			}
		}

		// Przepuść evidence do TopologyPayload (nodes[].evidence, edges[].evidence)
		nodes := convertNodes(uiTop.Nodes)
		edges := convertEdges(uiTop.Edges)

		// Uzupełnij Diagnostics.Devices i Diagnostics.Edges na bazie evidence z TopologyPayload
		// Devices
		if diag.Devices == nil {
			diag.Devices = map[string]DeviceEvidence{}
		}
		for _, n := range nodes {
			if n.Evidence != nil {
				diag.Devices[n.Id] = *n.Evidence
			}
		}
		// Edges
		if diag.Edges == nil {
			diag.Edges = map[string]EdgeEvidence{}
		}
		for _, e := range edges {
			if e.Evidence != nil {
				diag.Edges[e.Id] = *e.Evidence
			}
		}

		// Złóż odpowiedź
		resp := ScanResponse{Status: "ok"}
		if err != nil {
			resp.Status = "error"
			resp.Error = err.Error()
		} else {
			resp.Topology = TopologyPayload{
				Nodes: nodes,
				Edges: edges,
			}
			// jeśli użytkownik poprosił o CDP debug, przekaż sygnał do collectora przez Seeds/Target meta (tymczasowo: flagę w diag.Raw)
			if req.CDPDebug {
				if resp.Diagnostics.Raw == nil {
					resp.Diagnostics.Raw = map[string]interface{}{}
				}
				resp.Diagnostics.Raw["cdp"] = "enabled"
			}
			resp.Diagnostics = diag

			// Zapisz sesję skanu do workdir (topo.json, diag.json) i wykonaj merge do project.json
			if sess, err2 := wdm.NewScanSession(); err2 == nil {
				_ = wdm.SaveJSON(sess, "topo.json", resp.Topology)
				_ = wdm.SaveJSON(sess, "diag.json", resp.Diagnostics)
				// Merge do project.json (inkrementalny cache + historia)
				now := time.Now()
				_ = wdm.MergeProject(resp.Topology, resp.Diagnostics, now)
				// dodaj informację w odpowiedzi
				if resp.Diagnostics.Raw == nil {
					resp.Diagnostics.Raw = map[string]interface{}{}
				}
				resp.Diagnostics.Raw["savedTo"] = sess.Path
			} else {
				log.Printf("workdir session error: %v", err2)
			}
		}
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(resp)
	})

	// /api/debug/snmpwalk – BULKWALK wybranych OID-ów i zwrot OID->value (JSON)
	// Body: { "target":"ip-or-fqdn", "community":"public", "version":"v2c|v3", "oids": ["1.3.6....", "..."] }
	type dbgWalkReq struct {
		Target    string   `json:"target"`
		Community string   `json:"community"`
		Version   string   `json:"version"`
		Oids      []string `json:"oids"`
		V3User    string   `json:"v3user,omitempty"`
		V3Auth    string   `json:"v3authpass,omitempty"`
		V3Priv    string   `json:"v3privpass,omitempty"`
	}
	type dbgWalkResp struct {
		Status string                       `json:"status"`
		Data   map[string]map[string]string `json:"data,omitempty"` // oidRoot -> map[fullOID]value
		Error  string                       `json:"error,omitempty"`
	}
	mux.HandleFunc("/api/debug/snmpwalk", func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		defer r.Body.Close()
		var req dbgWalkReq
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			http.Error(w, "invalid JSON", http.StatusBadRequest)
			return
		}
		if strings.TrimSpace(req.Target) == "" || len(req.Oids) == 0 {
			http.Error(w, "target and oids are required", http.StatusBadRequest)
			return
		}
		cred := snmp.Credentials{Version: req.Version}
		if strings.ToLower(req.Version) == "v3" {
			cred.V3 = &snmp.AuthV3{User: req.V3User, AuthPass: req.V3Auth, PrivPass: req.V3Priv}
		} else {
			cred.Community = req.Community
		}
		col := snmp.NewGoSNMP()
		// otwórz sesję bez pipeline – bezpośrednio
		addr := req.Target
		if !strings.Contains(addr, ":") {
			addr = addr + ":161"
		}
		sess, err := col.OpenSessionForDebug(addr, cred)
		if err != nil {
			_ = json.NewEncoder(w).Encode(dbgWalkResp{Status: "error", Error: err.Error()})
			return
		}
		defer sess.Conn.Close()

		data := map[string]map[string]string{}
		for _, root := range req.Oids {
			root = strings.TrimSpace(root)
			if root == "" {
				continue
			}
			bucket := map[string]string{}
			_ = sess.BulkWalk(root, func(pdu gosnmp.SnmpPDU) error {
				val := ""
				switch v := pdu.Value.(type) {
				case string:
					val = v
				case []byte:
					val = string(v)
				default:
					val = fmt.Sprintf("%v", v)
				}
				bucket[pdu.Name] = val
				return nil
			})
			data[root] = bucket
		}
		w.Header().Set("Content-Type", "application/json")
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		_ = enc.Encode(dbgWalkResp{Status: "ok", Data: data})
	})

	// Static UI from embedded FS under cmd/auditopology/web
	// We need to strip the "web/" prefix so that "/" serves index.html located at cmd/auditopology/web/index.html
	sub, err := fs.Sub(webFS, "web")
	if err != nil {
		log.Fatal(err)
	}
	fileServer := http.FileServer(http.FS(sub))
	mux.Handle("/", fileServer)

	// Allow overriding port via PORT env variable (default 5173)
	port := os.Getenv("PORT")
	if port == "" {
		port = "5173"
	}
	srv := &http.Server{
		Addr:    ":" + port,
		Handler: mux,
	}

	go func() {
		log.Printf("AuditTopology bootstrap UI running at http://localhost%v\n", srv.Addr)
		if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatal(err)
		}
	}()

	// Wait for CTRL+C
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	<-sig
	log.Println("Shutting down...")
	_ = srv.Close()
}
