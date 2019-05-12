package main

import (
	"fmt"
	//	"github.com/davecgh/go-spew/spew"
	"bufio"
	"errors"
	nmap "github.com/lair-framework/go-nmap"
	"github.com/urfave/cli"
	"io/ioutil"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
)

func main() {
	var (
		target, targetList string = "", ""
	)

	app := cli.NewApp()
	app.Name = "scout"
	app.Usage = "scout will kickstart your enumeration process (and do most of it for you)"
	app.Flags = []cli.Flag{
		cli.StringFlag{
			Name:        "target,t",
			Usage:       "Specify a target hostname or IP address to enumerate",
			Destination: &target,
		},
		cli.StringFlag{
			Name:        "target-list,l",
			Usage:       "Specify a file to read a list of target hostnames or IP addresses to enumerate",
			Destination: &targetList,
		},
	}

	app.Action = func(c *cli.Context) error {
		var (
			err error
		)
		targets := []string{}

		//Lets load in some targets from the cli flags
		if targetList != "" {
			loadList, err := loadTargetList(targetList)
			if err != nil {
				return err
			}
			targets = append(targets, loadList...)
		} else if target != "" {
			targets = append(targets, target)
		} else {
			return errors.New("Error: It looks like you didn't provide a target or list of targets, try using -t and -l respectively")
		}

		//Create directory structure for scan output
		err = createDirectoryTree(targets)
		if err != nil {
			return err
		}

		for _, val := range targets {
			scan, err := nmapScan(val)
			if err != nil {
				return err
			}
			printTargetInfo(scan)
			enumeratePorts(val, scan)
		}
		return nil
	}

	err := app.Run(os.Args)
	if err != nil {
		log.Fatal(err)
	}
}

func printTargetInfo(target *nmap.NmapRun) {
	for _, host := range target.Hosts {
		if host.Addresses[0].AddrType == "ipv4" {
			fmt.Printf("Target: %s\n", host.Addresses[0].Addr)
		} else {
			fmt.Printf("Target: %s\n", host.Addresses[1].Addr)
		}
		fmt.Println("|\tOS Guessing:")
		for _, osGuess := range host.Os.OsMatches {
			fmt.Printf("|\t|\tName: %s - Accuracy: %s\n", osGuess.Name, osGuess.Accuracy)
		}

	}
}

func enumeratePorts(target string, scan *nmap.NmapRun) {
	openPorts := []nmap.Port{}
	fmt.Println("|\tOpen Ports:")
	for _, host := range scan.Hosts {
		for _, port := range host.Ports {
			if port.State.State == "open" {
				openPorts = append(openPorts, port)
				fmt.Printf("|\t|\tPort: %d Name: %s Product: %s Version: %s \n", port.PortId, port.Service.Name, port.Service.Product, port.Service.Version)
			}
		}
	}
	smbScanned := false
	for _, port := range openPorts {
		id := strconv.Itoa(port.PortId)
		name := port.Service.Name
		switch {
		case id == "80" || name == "http":
			gobusterScan(target, id, "http")
			gobusterCGIScan(target, id, "http")
			niktoScan(target, id, "http")
			vhostScan(target, id, "http")
		case id == "443" || name == "https":
			gobusterScan(target, id, "https")
			gobusterCGIScan(target, id, "https")
			niktoScan(target, id, "https")
			vhostScan(target, id, "https")
		case id == "139" || id == "445" || name == "smb" || name == "netbios-ssn":
			if !smbScanned {
				smbScan(target)
				nbtScan(target)
				enumfourlinuxScan(target)
				smbScanned = true
			}
		default:
			continue
		}
	}
}

func createDirectoryTree(targets []string) error {
	_ = syscall.Umask(000)
	base := "./targets"
	subdirs := []string{"scans", "exploit", "loot"}
	for _, target := range targets {
		for _, subdir := range subdirs {
			err := os.MkdirAll(filepath.Join(base, target, subdir), 0777)
			if err != nil {
				return err
			}
		}
	}
	return nil
}

func loadTargetList(filename string) ([]string, error) {
	f, err := os.Open(filename)
	if err != nil {
		return []string{}, err
	}
	scanner := bufio.NewScanner(f)
	result := []string{}
	for scanner.Scan() {
		line := scanner.Text()
		result = append(result, line)
	}
	return result, nil
}

func nmapScan(target string) (*nmap.NmapRun, error) {
	var (
		scan   *nmap.NmapRun
		cmdOut []byte
		err    error
	)
	path := filepath.Join("./targets", target, "scans", target+"_full.nmap")
	cmd := "nmap"
	args := []string{"-Pn", "-A", "-v", "-p-", "-oX", "-", "-oN", path, "-T", "4", target}
	fmt.Printf("Starting the following scan: %s %s\n", cmd, strings.Join(args[:], " "))
	if cmdOut, err = exec.Command(cmd, args...).Output(); err != nil {
		return nil, err
	}
	scan, err = nmap.Parse(cmdOut)
	if err != nil {
		return nil, err
	}
	return scan, nil
}

func gobusterScan(target string, port string, protocol string) {
	var (
		cmdOut []byte
		err error
	)
	path := filepath.Join("./targets", target, "scans", target+"_"+port+"_gobuster.txt")
	cmd := "gobuster"
	args := []string{"-w", "/usr/share/wordlists/dirbuster/directory-list-2.3-medium.txt", "-u", protocol + "://" + target + ":" + port, "-s", "'200,204,301,302,307,403,500'", "-e", "-k", "-t", "50"}
	fmt.Printf("Starting the following scan: %s %s\n", cmd, strings.Join(args[:], " "))
	if cmdOut, err = exec.Command(cmd, args...).Output(); err != nil {
		fmt.Println(string(cmdOut))
		fmt.Fprintln(os.Stderr, err)
		return
	}
	fmt.Println(string(cmdOut))
	err = ioutil.WriteFile(path, cmdOut, 0777)
	if err != nil {
		fmt.Println("couldn't write gobuster file")
		return
	}

	fmt.Println("Finished Gobuster Scan")
}

func gobusterCGIScan(target string, port string, protocol string) {
	var (
		cmdOut []byte
		err error
	)
	path := filepath.Join("./targets", target, "scans", target+"_"+port+"_cgi_gobuster.txt")
	cmd := "gobuster"
	args := []string{"-w", "/usr/share/seclists/Discovery/Web-Content/CGIs.txt", "-u", protocol + "://" + target + ":" + port, "-s", "'200,204,301,302,307,403,500'", "-e", "-k", "-t", "50"}
	fmt.Printf("Starting the following scan: %s %s\n", cmd, strings.Join(args[:], " "))
	if cmdOut, err = exec.Command(cmd, args...).Output(); err != nil {
		fmt.Println(string(cmdOut))
		fmt.Fprintln(os.Stderr, err)
		return
	}
	err = ioutil.WriteFile(path, cmdOut, 0777)
	if err != nil {
		fmt.Println("couldn't write gobuster CGI file")
		return
	}
	fmt.Println("Finished Gobuster CGI Scan")
	return
}

func niktoScan(target string, port string, protocol string) {
	var (
		err error
	)
	path := filepath.Join("./targets", target, "scans", target+"_"+port+"_nikto.txt")
	cmd := "nikto"
	args := []string{"-h", protocol + "://" + target, "-p", port, "-output", path}
	fmt.Printf("Starting the following scan: %s %s\n", cmd, strings.Join(args[:], " "))
	if err = exec.Command(cmd, args...).Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	fmt.Println("Finished Nikto Scan")
	return
}

func vhostScan(target string, port string, protocol string) {
	var (
		cmdOut []byte
		err error
	)
	path := filepath.Join("./targets", target, "scans", target+"_"+port+"_vhost.txt")
	cmd := "wfuzz"
	args := []string{"-h", protocol + "://FUZZ." + target + ":" + port}
	fmt.Printf("Starting the following scan: %s %s\n", cmd, strings.Join(args[:], " "))
	if err = exec.Command(cmd, args...).Run(); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return
	}
	err = ioutil.WriteFile(path, cmdOut, 0777)
	if err != nil {
		fmt.Println("couldn't write vhost file")
		return
	}
	fmt.Println("Finished vhost Scan")
	return
}

func smbScan(target string) {
	var (
		cmdOut []byte
		err    error
	)
	path := filepath.Join("./targets", target, "scans", target+"_smb.nmap")
	cmd := "nmap"
	args := []string{"-p", "445,139","-Pn", "-vv", "--script=smb-vuln*", "-oN", path, target}
	fmt.Printf("Starting the following scan: %s %s\n", cmd, strings.Join(args[:], " "))
	if cmdOut, err = exec.Command(cmd, args...).Output(); err != nil {
		fmt.Println("We've hit an issue!")
		fmt.Println(string(cmdOut))
		fmt.Fprintln(os.Stderr, err)
		return
	}
	fmt.Println("Finished SMB Nmap Scan")
	return

}

func enumfourlinuxScan(target string) {
	var (
		cmdOut []byte
		err    error
	)
	path := filepath.Join("./targets", target, "scans", target+"_enum4linux.txt")
	cmd := "enum4linux"
	args := []string{"-a", target}
	fmt.Printf("Starting the following scan: %s %s\n", cmd, strings.Join(args[:], " "))
	if cmdOut, err = exec.Command(cmd, args...).Output(); err != nil {
		fmt.Println("We've hit an issue!")
		fmt.Fprintln(os.Stderr, err)
		return
	}
	err = ioutil.WriteFile(path, cmdOut, 0777)
	if err != nil {
		fmt.Println("couldn't write enum4linux file")
		return
	}
	fmt.Println("Finished Enum4Linux Scan")
	return

}

func nbtScan(target string) {
	var (
		cmdOut []byte
		err    error
	)
	path := filepath.Join("./targets", target, "scans", target+"_nbtscan.txt")
	cmd := "nbtscan"
	args := []string{"-r", target}
	fmt.Printf("Starting the following scan: %s %s\n", cmd, strings.Join(args[:], " "))
	if cmdOut, err = exec.Command(cmd, args...).Output(); err != nil {
		fmt.Println("We've hit an issue!")
		fmt.Println(string(cmdOut))
		fmt.Fprintln(os.Stderr, err)
		return
	}

	err = ioutil.WriteFile(path, cmdOut, 0777)
	if err != nil {
		fmt.Println("couldn't write nbtScan file")
		return
	}

	fmt.Println("Finished nbtscan Scan")
	return

}
