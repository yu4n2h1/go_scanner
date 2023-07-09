package main

import (
	"flag"
	"fmt"
	"go_scanner/global"
	"go_scanner/icmp_scan"
	"go_scanner/ping_scan"
	"go_scanner/port_scan"
	"go_scanner/tools"
	"strconv"
	"strings"
)

func main() {
	global.CIDR = flag.String("h", "127.0.0.1/32", "Scan IP addresses based on input in CIDR notation.")

	// raddr := flag.String("i", "127.0.0.1", "Input the ip address you want to scan")
	// mask := flag.Int("m", 31, "Input the mask of target network")
	pingis := flag.Bool("ping", false, "Input the ping ro not")
	flag.Parse()
	args := strings.Split(*global.CIDR, "/")
	raddr := args[0]
	mask, err := strconv.Atoi(args[1])
	if err != nil {
		fmt.Println(err)
		return
	}

	// laddr := tools.Get_self(*raddr)
	var isping bool = *pingis
	min, max := tools.Get_ip_range(int(tools.Ip2int(raddr)), mask)
	ipslist := make([]string, max-min)
	for i := min; i <= max; i++ {
		ipslist = append(ipslist, tools.Int2ip(int32(i)))
	}
	var res []string
	if isping {
		res = ping_scan.CmdPing(ipslist)
	} else {
		res = icmp_scan.Icmp_scan2(ipslist)
	}
	fmt.Println(res)
	fmt.Println(len(res))

	for _, ip := range res {
		port_scan.Socket_scan(ip)
	}
}

// ip := "101.43.140.240"
// laddr := get_self(ip)
// fmt.Println(laddr)
// port_scan.Raw_socket_scan(laddr, ip)

// 172.17.1.202 -> [22 2027 1062 1061 3306 5355 80 8829 8830 2026 8839 40171]
