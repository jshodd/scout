package main

import (
	"fmt"
//	"github.com/davecgh/go-spew/spew"
	nmap "github.com/lair-framework/go-nmap"
	"os"
	"os/exec"
	"strconv"
)

func main() {
	var (
		scan   *nmap.NmapRun
		cmdOut []byte
		err    error
	)
	host := "10.11.1.5"
	cmd := "nmap"
	args := []string{"-sV", "-O", "-sC", "-oX", "-", "-T", "4", host}
	if cmdOut, err = exec.Command(cmd, args...).Output(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	scan, err = nmap.Parse(cmdOut)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	for _,host := range scan.Hosts {
		for _,address := range host.Addresses {
			if address.AddrType == "ipv4"{
				fmt.Println(address.Addr)
			}
		}
		for _,port := range host.Ports {
			fmt.Println(strconv.Itoa(port.PortId))
		}
	}

}
