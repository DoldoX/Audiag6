package snmp

// Stub interfaces and types for the SNMP collector MVP. This file defines
// the public contract and a no-op implementation returning sample data.
// Real SNMP logic (v2c/v3, LLDP/IF/BRIDGE/ARP) will be added in a next step.

import (
	"context"
	"errors"

	g "audiatopology/internal/graph"
)

type AuthV3 struct {
	User      string
	AuthProto string // MD5/SHA/SHA256...
	AuthPass  string
	PrivProto string // DES/AES128/AES256...
	PrivPass  string
}

type Credentials struct {
	Version string  // "v2c" or "v3"
	Community string
	V3       *AuthV3
}

type Target struct {
	Address      string // IP or FQDN
	Credentials  Credentials
}

// Collector defines what the SNMP module must expose.
// In MVP, we focus on L2-related data sufficient to deduce topology.
type Collector interface {
	// Discover performs a bounded discovery starting from given targets and
	// returns a partial L2 topology. Implementations should avoid write operations
	// and be rate-limited and read-only.
	Discover(ctx context.Context, targets []Target) (g.Topology, error)
}


// NoOpCollector is a minimal implementation that returns a static sample topology.
// Useful to validate the pipeline and UI without needing network access.
type NoOpCollector struct{}

func NewNoOp() *NoOpCollector {
	return &NoOpCollector{}
}

func (c *NoOpCollector) Discover(ctx context.Context, targets []Target) (g.Topology, error) {
	if len(targets) == 0 {
		return g.Topology{}, errors.New("no targets provided")
	}

	top := g.Topology{
		Devices: []g.Device{
			{ID: "core1", Name: "CORE-1", Vendor: "cisco", Role: "core"},
			{ID: "dist1", Name: "DIST-1", Vendor: "aruba", Role: "distribution"},
			{ID: "dist2", Name: "DIST-2", Vendor: "juniper", Role: "distribution"},
			{ID: "acc1", Name: "ACC-1", Vendor: "mikrotik", Role: "access"},
			{ID: "acc2", Name: "ACC-2", Vendor: "hpe", Role: "access"},
		},
		Links: []g.Link{
			{ID: "e1", ADeviceID: "core1", AIfName: "Te1/1", BDeviceID: "dist1", BIfName: "Te1/1", Type: "trunk", Label: "10,20,30", Score: "high"},
			{ID: "e2", ADeviceID: "core1", AIfName: "Te1/2", BDeviceID: "dist2", BIfName: "Te1/2", Type: "trunk", Label: "10,20,30", Score: "high"},
			{ID: "e3", ADeviceID: "dist1", AIfName: "Gi1/0/1", BDeviceID: "acc1", BIfName: "Gi1/0/24", Type: "trunk", Label: "10,20", Score: "medium"},
			{ID: "e4", ADeviceID: "dist2", AIfName: "Gi1/0/2", BDeviceID: "acc2", BIfName: "Gi1/0/24", Type: "access", Label: "10", Score: "medium"},
		},
	}
	return top, nil
}
