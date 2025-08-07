package snmp

// Minimal real SNMP collector (v2c/v3) that fetches LLDP local/remote and IF-MIB basics
// from provided seed devices and builds a tiny L2 graph. This is an MVP and intentionally
// limited: it reads a subset needed to prove end-to-end technical flow.

import (
	"context"
	"fmt"
	"net"
	"slices"
	"sort"
	"strings"
	"time"

	g "audiatopology/internal/graph"
	"github.com/gosnmp/gosnmp"
)

type GoSNMPCollector struct {
	Timeout   time.Duration
	Retries   int
	MaxOids   int
	BulkSize  uint8
}

func NewGoSNMP() *GoSNMPCollector {
	return &GoSNMPCollector{
		Timeout:  3 * time.Second,
		Retries:  1,
		MaxOids:  24,
		BulkSize: 20,
	}
}

func (c *GoSNMPCollector) Discover(ctx context.Context, targets []Target) (g.Topology, error) {
	top := g.Topology{}
	// track per-device evidence
	devEvidence := map[string]*g.DeviceEvidence{}
	seen := map[string]bool{}
	// simple debug sink to attach raw CDP OIDs (filled only for the first target for now)
	rawCDP := map[string]string{}

	// temporary storage for FDB data per device to correlate after scanning all seeds
	deviceFDB := map[string]deviceFDBEntry{}

	for _, t := range targets {
		select {
		case <-ctx.Done():
			return top, ctx.Err()
		default:
		}

		addr := t.Address
		if _, _, err := net.SplitHostPort(addr); err != nil {
			addr = net.JoinHostPort(addr, "161")
		}

		sn, err := c.openSession(addr, t.Credentials)
		if err != nil {
			continue // skip seed on error (MVP harden: collect errors)
		}
		defer sn.Conn.Close()

		sysName := getString(sn, ".1.3.6.1.2.1.1.5.0")  // sysName.0
		sysDescr := getString(sn, ".1.3.6.1.2.1.1.1.0") // sysDescr.0
		deviceID := normalizeID(sysName, addr)

		if !seen[deviceID] {
			top.Devices = append(top.Devices, g.Device{
				ID:       deviceID,
				Name:     firstNonEmpty(sysName, deviceID),
				Vendor:   guessVendor(sysDescr),
				Role:     "unknown",
				SysDescr: sysDescr,
			})
			seen[deviceID] = true
		}
		// initialize per-device evidence bucket
		if _, ok := devEvidence[deviceID]; !ok {
			devEvidence[deviceID] = &g.DeviceEvidence{}
		}

		// Read ifName (IF-MIB::ifName) and ifDescr
		ifNames := walkStringIndex(sn, ".1.3.6.1.2.1.31.1.1.1.1") // ifName
		ifDescr := walkStringIndex(sn, ".1.3.6.1.2.1.2.2.1.2")    // ifDescr

		// CDP (CISCO-CDP-MIB) – neighbors (high confidence)
		// Tables:
		// - cdpCacheDeviceId:   1.3.6.1.4.1.9.9.23.1.2.1.1.6
		// - cdpCacheDevicePort: 1.3.6.1.4.1.9.9.23.1.2.1.1.7
		// - cdpCacheCapabilities: 1.3.6.1.4.1.9.9.23.1.2.1.1.9
		// - cdpInterfaceIfIndex: 1.3.6.1.4.1.9.9.23.1.2.1.1.2 (best-effort, not always populated)
		// SUROWY ZRZUT (debug): zbierz pełne pary OID→value dla powyższych tablic, aby dopasować indeksację na różnych platformach (np. SG300)
		addRawWalk(sn, ".1.3.6.1.4.1.9.9.23.1.2.1.1.6", rawCDP)
		addRawWalk(sn, ".1.3.6.1.4.1.9.9.23.1.2.1.1.7", rawCDP)
		addRawWalk(sn, ".1.3.6.1.4.1.9.9.23.1.2.1.1.9", rawCDP)
		addRawWalk(sn, ".1.3.6.1.4.1.9.9.23.1.2.1.1.2", rawCDP)

		cdpDevIDs := walkString(sn, ".1.3.6.1.4.1.9.9.23.1.2.1.1.6")
		cdpDevPorts := walkString(sn, ".1.3.6.1.4.1.9.9.23.1.2.1.1.7")
		cdpCaps := walkInt(sn, ".1.3.6.1.4.1.9.9.23.1.2.1.1.9")
		cdpLocalIf := walkInt(sn, ".1.3.6.1.4.1.9.9.23.1.2.1.1.2")

		for i := 0; i < len(cdpDevIDs); i++ {
			peerName := cdpDevIDs[i]
			peerPort := ""
			if i < len(cdpDevPorts) {
				peerPort = cdpDevPorts[i]
			}
			var capStr string
			if i < len(cdpCaps) {
				capStr = fmt.Sprintf("0x%x", cdpCaps[i])
			}
			localIf := ""
			if i < len(cdpLocalIf) && cdpLocalIf[i] > 0 {
				idx := cdpLocalIf[i]
				localIf = ifNames[idx]
				if localIf == "" {
					localIf = ifDescr[idx]
				}
				if localIf == "" {
					localIf = fmt.Sprintf("ifIndex%d", idx)
				}
			}

			peerID := normalizeID(peerName, "")
			if peerID == "" {
				peerID = fmt.Sprintf("peer-%s", sanitize(peerName))
			}
			if !seen[peerID] {
				top.Devices = append(top.Devices, g.Device{
					ID:     peerID,
					Name:   firstNonEmpty(peerName, peerID),
					Role:   "unknown",
					Vendor: "",
				})
				seen[peerID] = true
			}

			lbl := peerPort
			if localIf != "" && peerPort != "" {
				lbl = fmt.Sprintf("%s ↔ %s", localIf, peerPort)
			}

			// Merge with existing LLDP edge if present between same endpoints
			edgeID := fmt.Sprintf("%s:%s-%s:%s", deviceID, localIf, peerID, peerPort)
			merged := false
			for ei := range top.Links {
				e := &top.Links[ei]
				sameAB := e.ADeviceID == deviceID && e.BDeviceID == peerID
				samePorts := (localIf == "" || e.AIfName == localIf) && (peerPort == "" || e.BIfName == peerPort)
				if sameAB && samePorts {
					// upgrade confidence to high and attach/merge evidence
					e.Score = "high"
					if e.Evidence == nil {
						e.Evidence = &g.EdgeEvidence{}
					}
					e.Evidence.Source = "cdp"
					e.Evidence.Confidence = "high"
					e.Evidence.A = g.EdgeEndpoint{Device: deviceID, If: firstNonEmpty(localIf, e.AIfName)}
					e.Evidence.B = g.EdgeEndpoint{Device: peerID, If: firstNonEmpty(peerPort, e.BIfName)}
					if capStr != "" {
						// append capability info to UsedOids as note or store into SampleMacs array as generic text; better: extend UsedOids + meta
						e.Evidence.UsedOids = append(e.Evidence.UsedOids,
							"1.3.6.1.4.1.9.9.23.1.2.1.1.6", // cdpCacheDeviceId
							"1.3.6.1.4.1.9.9.23.1.2.1.1.7", // cdpCacheDevicePort
							"1.3.6.1.4.1.9.9.23.1.2.1.1.9", // cdpCacheCapabilities
						)
						// we don't have dedicated field for capabilities; include as sampleMacs textual hint
						e.Evidence.SampleMacs = append(e.Evidence.SampleMacs, "cdpCaps="+capStr)
					}
					merged = true
					break;
				}
			}
			if merged {
				continue
			}

			// otherwise add new high-confidence edge
			evCaps := []string{
				"1.3.6.1.4.1.9.9.23.1.2.1.1.6",
				"1.3.6.1.4.1.9.9.23.1.2.1.1.7",
				"1.3.6.1.4.1.9.9.23.1.2.1.1.9",
			}
			sm := []string{}
			if capStr != "" {
				sm = append(sm, "cdpCaps="+capStr)
			}
			top.Links = append(top.Links, g.Link{
				ID:        edgeID,
				ADeviceID: deviceID,
				AIfName:   localIf,
				BDeviceID: peerID,
				BIfName:   peerPort,
				Type:      "link",
				Label:     lbl,
				Score:     "high",
				Evidence: &g.EdgeEvidence{
					Source:     "cdp",
					Confidence: "high",
					A:          g.EdgeEndpoint{Device: deviceID, If: localIf},
					B:          g.EdgeEndpoint{Device: peerID, If: peerPort},
					UsedOids:   evCaps,
					SampleMacs: sm,
				},
			})
		}

		// LLDP local/remote counts and details
		// remote:
		// remSysName: 1.0.8802.1.1.2.1.4.1.1.9
		// remPortId:  1.0.8802.1.1.2.1.4.1.1.7
		// remLocalPortNum (index): 1.0.8802.1.1.2.1.4.1.1.2
		remSysNames := walkString(sn, ".1.0.8802.1.1.2.1.4.1.1.9")
		remPortIds := walkString(sn, ".1.0.8802.1.1.2.1.4.1.1.7")
		remLocalPortNums := walkInt(sn, ".1.0.8802.1.1.2.1.4.1.1.2")
		// local:
		locPortDesc := walkStringIndex(sn, ".1.0.8802.1.1.2.1.3.7.1.4")
		devEvidence[deviceID].LldpRemoteCount = len(remSysNames)
		// We approximate local count as number of ports that have description in lldpLocPortDesc
		devEvidence[deviceID].LldpLocalCount = len(locPortDesc)

		// Build links based on LLDP rem entries: indexes pattern (chassisId, portId, localPortNum) — we only use localPortNum
		for i := 0; i < len(remSysNames) && i < len(remPortIds) && i < len(remLocalPortNums); i++ {
			peerName := remSysNames[i]
			peerPort := remPortIds[i]
			localNum := remLocalPortNums[i]
			localIf := ifNames[localNum]
			if localIf == "" {
				localIf = ifDescr[localNum]
			}
			if localIf == "" {
				localIf = fmt.Sprintf("ifIndex%d", localNum)
			}
 
			peerID := normalizeID(peerName, "")
			if peerID == "" {
				peerID = fmt.Sprintf("peer-%s", sanitize(peerName))
			}
			if !seen[peerID] {
				top.Devices = append(top.Devices, g.Device{
					ID:     peerID,
					Name:   firstNonEmpty(peerName, peerID),
					Role:   "unknown",
					Vendor: "",
				})
				seen[peerID] = true
			}
 
			lbl := peerPort
			if d, ok := locPortDesc[localNum]; ok && d != "" {
				lbl = fmt.Sprintf("%s ↔ %s", localIf, peerPort)
			}
 
			// Attach evidence for LLDP high-confidence edge
			usedOids := []string{
				".1.0.8802.1.1.2.1.4.1.1.9", // rem sysName
				".1.0.8802.1.1.2.1.4.1.1.7", // rem portId
				".1.0.8802.1.1.2.1.4.1.1.2", // rem localPortNum
				".1.0.8802.1.1.2.1.3.7.1.4", // loc port desc
				".1.3.6.1.2.1.31.1.1.1.1",   // ifName
				".1.3.6.1.2.1.2.2.1.2",      // ifDescr
			}
			top.Links = append(top.Links, g.Link{
				ID:        fmt.Sprintf("%s:%s-%s:%s", deviceID, localIf, peerID, peerPort),
				ADeviceID: deviceID,
				AIfName:   localIf,
				BDeviceID: peerID,
				BIfName:   peerPort,
				Type:      "link",
				Label:     lbl,
				Score:     "high",
				Evidence: &g.EdgeEvidence{
					Source:     "lldp",
					Confidence: "high",
					A:          g.EdgeEndpoint{Device: deviceID, If: localIf},
					B:          g.EdgeEndpoint{Device: peerID, If: peerPort},
					UsedOids:   usedOids,
				},
			})
		}

		// Fallback: BRIDGE/Q-BRIDGE FDB + VLAN korelacja (confidence=medium)
		// dot1dBasePortIfIndex: 1.3.6.1.2.1.17.1.4.1.2
		basePortToIf := walkIntIndex(sn, ".1.3.6.1.2.1.17.1.4.1.2") // map[bridgePort]ifIndex

		// dot1q FDB: vlan -> list of (mac -> bridgePort)
		type macOnPort struct {
			Vlan int
			Mac  string
			Port int
		}
		var fdb []macOnPort
		// dot1qTpFdbPort: 1.3.6.1.2.1.17.7.1.2.2.1.2
		// Index: vlan.mac(6 bytes). Parse last 7 numbers: vlan + 6 MAC bytes.
		errFDBWalk := sn.BulkWalk(".1.3.6.1.2.1.17.7.1.2.2.1.2", func(p gosnmp.SnmpPDU) error {
			port := toInt(p.Value)
			if port <= 0 {
				return nil
			}
			vlan, mac := parseDot1qIndex(p.Name)
			if vlan == 0 || mac == "" {
				return nil
			}
			fdb = append(fdb, macOnPort{Vlan: vlan, Mac: mac, Port: port})
			return nil
		})
		if errFDBWalk != nil {
			// record OID error into per-device evidence
			if devEvidence[deviceID] != nil {
				devEvidence[deviceID].OidErrors = append(devEvidence[deviceID].OidErrors, fmt.Sprintf("walk dot1qTpFdbPort error: %v", errFDBWalk))
			}
		}
		// compute per-device evidence: total FDB entries and VLAN count
		devEvidence[deviceID].FdbTotalEntries += len(fdb)
		{
			vlanSet := map[int]struct{}{}
			for _, e := range fdb {
				vlanSet[e.Vlan] = struct{}{}
			}
			devEvidence[deviceID].VlanCount += len(vlanSet)
		}

		// Zbuduj mapę ifIndex -> {vlan -> set(mac)}
		ifVlanMacs := map[int]map[int]map[string]struct{}{}
		for _, e := range fdb {
			ifIndex := basePortToIf[e.Port]
			if ifIndex == 0 {
				continue
			}
			if _, ok := ifVlanMacs[ifIndex]; !ok {
				ifVlanMacs[ifIndex] = map[int]map[string]struct{}{}
			}
			if _, ok := ifVlanMacs[ifIndex][e.Vlan]; !ok {
				ifVlanMacs[ifIndex][e.Vlan] = map[string]struct{}{}
			}
			// pomijamy multicast/broadcast
			if !isUnicastMac(e.Mac) {
				continue
			}
			ifVlanMacs[ifIndex][e.Vlan][e.Mac] = struct{}{}
		}

		// Na razie korelacja wewnątrz jednego urządzenia nie tworzy krawędzi.
		// Krawędzie tworzymy, gdy w innym seedzie zobaczymy te same MAC/VLAN na innym switchu.
		// Dlatego na końcu pętli odkładamy wynik do pamięci tymczasowej, a po całym obiegu łączymy.
		deviceFDB[deviceID] = deviceFDBEntry{
			IfVlanMacs: ifVlanMacs,
			IfNames:    ifNames,
			IfDescr:    ifDescr,
		}
	}

	// Korelacja między urządzeniami (confidence=medium): wspólne MAC w tym samym VLAN
	buildFDBLinks(&top, deviceFDB)

	// attach per-device evidence to device structs
	for i := range top.Devices {
		if ev, ok := devEvidence[top.Devices[i].ID]; ok {
			top.Devices[i].Evidence = ev
		}
	}

	// Jeśli mamy surowy zrzut CDP – zapisz go do top.Raw, by UI mógł go pokazać (Diagnostics.Raw w API)
	if len(rawCDP) > 0 {
		if top.Raw == nil {
			top.Raw = map[string]map[string]string{}
		}
		top.Raw["cdp"] = rawCDP
	}

	return top, nil
}

func (c *GoSNMPCollector) openSession(addr string, cred Credentials) (*gosnmp.GoSNMP, error) {
	cfg := &gosnmp.GoSNMP{
		Target:    strings.Split(addr, ":")[0],
		Port:      uint16(parsePort(addr, 161)),
		Timeout:   c.Timeout,
		Retries:   c.Retries,
		MaxOids:   c.MaxOids,
		MaxRepetitions: uint32(c.BulkSize),
	}

	switch strings.ToLower(cred.Version) {
	case "v3":
		cfg.Version = gosnmp.Version3
		cfg.SecurityModel = gosnmp.UserSecurityModel
		u := &gosnmp.UsmSecurityParameters{UserName: cred.V3.User}
		// Minimal MVP – treat presence of fields as enabling auth/priv:
		if cred.V3.AuthPass != "" {
			u.AuthenticationPassphrase = cred.V3.AuthPass
			u.AuthenticationProtocol = gosnmp.SHA // default
		}
		if cred.V3.PrivPass != "" {
			u.PrivacyPassphrase = cred.V3.PrivPass
			u.PrivacyProtocol = gosnmp.AES
		}
		cfg.SecurityParameters = u
	case "v2c", "2c", "":
		cfg.Version = gosnmp.Version2c
		cfg.Community = firstNonEmpty(cred.Community, "public")
	default:
		cfg.Version = gosnmp.Version2c
		cfg.Community = firstNonEmpty(cred.Community, "public")
	}

	if err := cfg.Connect(); err != nil {
		return nil, err
	}
	return cfg, nil
}

// OpenSessionForDebug exposes a session opener for debug endpoints (no pipeline)
func (c *GoSNMPCollector) OpenSessionForDebug(addr string, cred Credentials) (*gosnmp.GoSNMP, error) {
	return c.openSession(addr, cred)
}

// Helpers

func getString(sn *gosnmp.GoSNMP, oid string) string {
	p, err := sn.Get([]string{oid})
	if err != nil || len(p.Variables) == 0 {
		return ""
	}
	if s, ok := p.Variables[0].Value.(string); ok {
		return s
	}
	// Some devices return OctetString as []byte; make it printable.
	if b, ok := p.Variables[0].Value.([]byte); ok {
		return string(b)
	}
	return fmt.Sprintf("%v", p.Variables[0].Value)
}

func walkString(sn *gosnmp.GoSNMP, oid string) []string {
	out := []string{}
	_ = sn.BulkWalk(oid, func(pdu gosnmp.SnmpPDU) error {
		if s, ok := pdu.Value.(string); ok {
			out = append(out, s)
		} else if b, ok := pdu.Value.([]byte); ok {
			out = append(out, string(b))
		} else {
			out = append(out, fmt.Sprintf("%v", pdu.Value))
		}
		return nil
	})
	return out
}

func walkInt(sn *gosnmp.GoSNMP, oid string) []int {
	out := []int{}
	_ = sn.BulkWalk(oid, func(pdu gosnmp.SnmpPDU) error {
		out = append(out, toInt(pdu.Value))
		return nil
	})
	return out
}

func walkStringIndex(sn *gosnmp.GoSNMP, oid string) map[int]string {
	out := map[int]string{}
	_ = sn.BulkWalk(oid, func(pdu gosnmp.SnmpPDU) error {
		out[indexFromOid(pdu.Name)] = valueToString(pdu.Value)
		return nil
	})
	return out
}

func walkIntIndex(sn *gosnmp.GoSNMP, oid string) map[int]int {
	out := map[int]int{}
	_ = sn.BulkWalk(oid, func(pdu gosnmp.SnmpPDU) error {
		out[indexFromOid(pdu.Name)] = toInt(pdu.Value)
		return nil
	})
	return out
}

func indexFromOid(name string) int {
	i := strings.LastIndex(name, ".")
	if i < 0 {
		return 0
	}
	return toInt(name[i+1:])
}

// Parse dot1qTpFdbPort index -> (vlan, mac) from OID suffix
// e.g. ...1.2.<vlan>.<mac6octets>
func parseDot1qIndex(oid string) (int, string) {
	parts := strings.Split(oid, ".")
	if len(parts) < 8 {
		return 0, ""
	}
	// take last 7 numbers: vlan + 6 bytes
	var nums []int
	for i := len(parts) - 7; i < len(parts); i++ {
		n := 0
		fmt.Sscanf(parts[i], "%d", &n)
		nums = append(nums, n)
	}
	if len(nums) != 7 {
		return 0, ""
	}
	vlan := nums[0]
	mac := fmt.Sprintf("%02x:%02x:%02x:%02x:%02x:%02x", nums[1], nums[2], nums[3], nums[4], nums[5], nums[6])
	return vlan, mac
}

func isUnicastMac(m string) bool {
	if len(m) != 17 {
		return false
	}
	// first octet LSB of first byte indicates multicast
	var b0 int
	_, _ = fmt.Sscanf(m[0:2], "%x", &b0)
	return (b0&1) == 0
}

func toInt(v interface{}) int {
	switch t := v.(type) {
	case int:
		return t
	case uint, uint32, uint64:
		return int(gosnmp.ToBigInt(v).Int64())
	case int32, int64:
		return int(gosnmp.ToBigInt(v).Int64())
	case string:
		n := 0
		fmt.Sscanf(t, "%d", &n)
		return n
	default:
		return int(gosnmp.ToBigInt(v).Int64())
	}
}

func valueToString(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	if b, ok := v.([]byte); ok {
		return string(b)
	}
	return fmt.Sprintf("%v", v)
}

// addRawWalk collects raw OID→value pairs into dst map (best effort; ignores errors)
func addRawWalk(sn *gosnmp.GoSNMP, oid string, dst map[string]string) {
	_ = sn.BulkWalk(oid, func(p gosnmp.SnmpPDU) error {
		dst[p.Name] = valueToString(p.Value)
		return nil
	})
}

type deviceFDBEntry struct {
	IfVlanMacs map[int]map[int]map[string]struct{} // ifIndex -> vlan -> set(mac)
	IfNames    map[int]string
	IfDescr    map[int]string
}

func buildFDBLinks(top *g.Topology, fdb map[string]deviceFDBEntry) {
	// iterate pairs of devices and search VLAN where they share host MACs learned on access ports
	type edgeCand struct {
		aDev, aIf string
		bDev, bIf string
		vlan      int
		score     string
		shared    int
		samples   []string
	}
	var edges []edgeCand

	// devices list
	var devIDs []string
	for id := range fdb {
		devIDs = append(devIDs, id)
	}
	sort.Strings(devIDs)

	for i := 0; i < len(devIDs); i++ {
		for j := i + 1; j < len(devIDs); j++ {
			da := devIDs[i]
			db := devIDs[j]
			a := fdb[da]
			b := fdb[db]
			// iterate vlan present in both
			vlans := unionKeys(a.IfVlanMacs, b.IfVlanMacs)
			for _, vlan := range vlans {
				for aIf, aV := range a.IfVlanMacs {
					mA, okA := aV[vlan]
					if !okA {
						continue
					}
					for bIf, bV := range b.IfVlanMacs {
						mB, okB := bV[vlan]
						if !okB {
							continue
						}
						// intersection size (shared hosts) – if there are common MACs on both interfaces in same VLAN,
						// it's very likely these ports are uplinked
						shared := interSize(mA, mB)
						if shared >= 3 { // threshold 3 host MACs
							aName := firstNonEmpty(a.IfNames[aIf], a.IfDescr[aIf], fmt.Sprintf("ifIndex%d", aIf))
							bName := firstNonEmpty(b.IfNames[bIf], b.IfDescr[bIf], fmt.Sprintf("ifIndex%d", bIf))
							edges = append(edges, edgeCand{
								aDev: da, aIf: aName, bDev: db, bIf: bName, vlan: vlan, score: "medium", shared: shared,
								samples: sampleMacs(mA, mB, 5),
							})
						}
					}
				}
			}
		}
	}

	// de-duplicate edges
	seen := map[string]bool{}
	for _, e := range edges {
		id1 := fmt.Sprintf("%s:%s-%s:%s", e.aDev, e.aIf, e.bDev, e.bIf)
		id2 := fmt.Sprintf("%s:%s-%s:%s", e.bDev, e.bIf, e.aDev, e.aIf)
		if seen[id1] || seen[id2] {
			continue
		}
		seen[id1] = true
		lbl := fmt.Sprintf("VLAN %d", e.vlan)
		// attach evidence to the link
		v := e.vlan
		top.Links = append(top.Links, g.Link{
			ID:        id1,
			ADeviceID: e.aDev,
			AIfName:   e.aIf,
			BDeviceID: e.bDev,
			BIfName:   e.bIf,
			Type:      "trunk",
			Label:     lbl,
			Score:     e.score,
			Evidence: &g.EdgeEvidence{
				Source:     "fdb",
				Confidence: "medium",
				A:          g.EdgeEndpoint{Device: e.aDev, If: e.aIf},
				B:          g.EdgeEndpoint{Device: e.bDev, If: e.bIf},
				VLAN:       &v,
				SharedMacs: e.shared,
				SampleMacs: e.samples,
				UsedOids: []string{
					".1.3.6.1.2.1.17.1.4.1.2",       // dot1dBasePortIfIndex
					".1.3.6.1.2.1.17.7.1.2.2.1.2",   // dot1qTpFdbPort
				},
			},
		})
	}
}

func unionKeys(a, b map[int]map[int]map[string]struct{}) []int {
	seen := map[int]struct{}{}
	for _, v := range a {
		for vlan := range v {
			seen[vlan] = struct{}{}
		}
	}
	for _, v := range b {
		for vlan := range v {
			seen[vlan] = struct{}{}
		}
	}
	var out []int
	for k := range seen {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

func interSize(a, b map[string]struct{}) int {
	n := 0
	for k := range a {
		if _, ok := b[k]; ok {
			n++
		}
	}
	return n
}

func sampleMacs(a, b map[string]struct{}, limit int) []string {
	out := []string{}
	for k := range a {
		if _, ok := b[k]; ok {
			out = append(out, k)
			if len(out) >= limit {
				break
			}
		}
	}
	slices.Sort(out)
	return out
}

func guessVendor(sysDescr string) string {
	l := strings.ToLower(sysDescr)
	switch {
	case strings.Contains(l, "cisco"):
		return "cisco"
	case strings.Contains(l, "aruba"), strings.Contains(l, "hewlett"), strings.Contains(l, "hpe"):
		return "aruba"
	case strings.Contains(l, "juniper"):
		return "juniper"
	case strings.Contains(l, "mikrotik"):
		return "mikrotik"
	case strings.Contains(l, "huawei"):
		return "huawei"
	case strings.Contains(l, "fortinet"):
		return "fortinet"
	default:
		return ""
	}
}

func normalizeID(sysName, addr string) string {
	if sysName != "" {
		return sanitize(sysName)
	}
	if addr != "" {
		host := strings.Split(addr, ":")[0]
		return sanitize(host)
	}
	return ""
}

func sanitize(s string) string {
	out := strings.TrimSpace(strings.ToLower(s))
	out = strings.ReplaceAll(out, " ", "-")
	out = strings.ReplaceAll(out, ".", "-")
	out = strings.ReplaceAll(out, "_", "-")
	return out
}

func firstNonEmpty(vals ...string) string {
	for _, v := range vals {
		if strings.TrimSpace(v) != "" {
			return v
		}
	}
	return ""
}

func parsePort(hostport string, def int) int {
	parts := strings.Split(hostport, ":")
	if len(parts) == 2 {
		var p int
		fmt.Sscanf(parts[1], "%d", &p)
		if p > 0 {
			return p
		}
	}
	return def
}
