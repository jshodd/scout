package main

import (
	"fmt"
//	"github.com/davecgh/go-spew/spew"
	nmap "github.com/lair-framework/go-nmap"
	"os"
	"log"
	"os/exec"
	"strings"
	"strconv"
	"github.com/urfave/cli"
)

func main(){
	app:= cli.NewApp()
	app.Name = "scout"
	app.Usage = "scout will kickstart your enumeration process (and do most of it for you)"
	app.Action = nmapScan
	err := app.Run(os.Args)
	if err != nil{
		log.Fatal(err)
	}
}


func nmapScan(c *cli.Context) error {
	var (
		scan   *nmap.NmapRun
		cmdOut []byte
		err    error
	)
	host := c.Args().Get(0)
	cmd := "nmap"
	args := []string{"-sV", "-O", "-p-", "-oX", "-", "-T", "4", host}
	fmt.Printf("Starting the following scan: %s %s\n",cmd, strings.Join(args[:]," "))
	if cmdOut, err = exec.Command(cmd, args...).Output(); err != nil {
		return err
	}
	scan, err = nmap.Parse(cmdOut)
	if err != nil {
		return err
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
	return nil
}
