package main

import (
	"flag"
	"fmt"
	"time"

	VRRP "github.com/jwmu/VRRP-go/vrrp"
)

var (
	VRID     int
	Priority int
)

func init() {
	flag.IntVar(&VRID, "vrid", 233, "virtual router ID")
	flag.IntVar(&Priority, "pri", 100, "router priority")
}

func main() {
	flag.Parse()
	vr, err := VRRP.NewVirtualRouter(byte(VRID), "ens3", false, VRRP.IPv4)
	if err != nil {
		fmt.Printf("NewVirtualRouter: %v\n", err)
		return
	}
	vr.SetPriorityAndMasterAdvInterval(byte(Priority), time.Millisecond*800)
	vr.Enroll(VRRP.Backup2Master, func(int) {
		fmt.Println("init to master")
	})
	vr.Enroll(VRRP.Master2Init, func(int) {
		fmt.Println("master to init")
	})
	vr.Enroll(VRRP.Master2Backup, func(int) {
		fmt.Println("master to backup")
	})
	go func() {
		time.Sleep(time.Minute * 5)
		vr.Stop()
	}()
	vr.StartWithEventSelector()

}
