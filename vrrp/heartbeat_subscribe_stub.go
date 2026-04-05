//go:build !linux

package vrrp

import "fmt"

type heartbeatLinkUpdate struct {
	Name  string
	Index int
	Up    bool
}

func defaultHeartbeatSubscribe(_ string, _ byte, ch chan<- heartbeatLinkUpdate, done <-chan struct{}) error {
	return fmt.Errorf("heartbeat address subscription is only supported on linux")
}
