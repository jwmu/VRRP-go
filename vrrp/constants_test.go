package vrrp

import "testing"

func TestVRRPVersionString(t *testing.T) {
	tests := []struct {
		v    VRRPVersion
		want string
	}{
		{VRRPv1, "VRRPVersion1"},
		{VRRPv2, "VRRPVersion2"},
		{VRRPv3, "VRRPVersion3"},
		{VRRPVersion(99), "unknown VRRP version"},
	}
	for _, tt := range tests {
		if got := tt.v.String(); got != tt.want {
			t.Errorf("VRRPVersion(%d).String() = %q, want %q", tt.v, got, tt.want)
		}
	}
}

func TestEVENTString(t *testing.T) {
	tests := []struct {
		e    EVENT
		want string
	}{
		{START, "START"},
		{SHUTDOWN, "SHUTDOWN"},
		{HEARTBEAT_UP, "HEARTBEAT_UP"},
		{HEARTBEAT_DOWN, "HEARTBEAT_DOWN"},
		{EVENT(99), "unknown event"},
	}
	for _, tt := range tests {
		if got := tt.e.String(); got != tt.want {
			t.Errorf("EVENT(%d).String() = %q, want %q", tt.e, got, tt.want)
		}
	}
}

func TestGratuitousARPOperationString(t *testing.T) {
	tests := []struct {
		o    GratuitousARPOperation
		want string
	}{
		{GratuitousARPRequest, "request"},
		{GratuitousARPReply, "reply"},
		{GratuitousARPOperation(99), "unknown"},
	}
	for _, tt := range tests {
		if got := tt.o.String(); got != tt.want {
			t.Errorf("GratuitousARPOperation(%d).String() = %q, want %q", tt.o, got, tt.want)
		}
	}
}

func TestTransitionString(t *testing.T) {
	tests := []struct {
		tr   transition
		want string
	}{
		{Master2Backup, "master to backup"},
		{Backup2Master, "backup to master"},
		{Init2Master, "init to master"},
		{Init2Backup, "init to backup"},
		{Backup2Init, "backup to init"},
		{Master2Init, "master to init"},
		{Master2Fault, "master to fault"},
		{Backup2Fault, "backup to fault"},
		{Init2Fault, "init to fault"},
		{Fault2Master, "fault to master"},
		{Fault2Backup, "fault to backup"},
		{transition(99), "unknown transition"},
	}
	for _, tt := range tests {
		if got := tt.tr.String(); got != tt.want {
			t.Errorf("transition(%d).String() = %q, want %q", tt.tr, got, tt.want)
		}
	}
}
