package main

import (
	"flag"
	"fmt"
	"go_scanner/global"
	"go_scanner/icmp_scan"
	"go_scanner/ping_scan"
	"go_scanner/port_scan"
	"go_scanner/tools"
	"sort"
	"strconv"
	"strings"
)

func main() {
	global.CIDR = flag.String("h", "127.0.0.1/32", "Scan IP addresses based on input in CIDR notation.")

	pingis := flag.Bool("ping", false, "Input the ping ro not")
	flag.Parse()
	var err error
	if strings.Contains(*global.CIDR, "/") {
		args := strings.Split(*global.CIDR, "/")
		global.Raddr = args[0]
		global.Mask, err = strconv.Atoi(args[1])
	} else {
		global.Mask = 32
		global.Raddr = *global.CIDR
	}
	if err != nil {
		fmt.Println(err)
		return
	}

	// laddr := tools.Get_self(*raddr)
	var isping bool = *pingis
	min, max := tools.Get_ip_range(int(tools.Ip2int(global.Raddr)), global.Mask)
	ipslist := make([]string, max-min)
	for i := min; i <= max; i++ {
		ipslist = append(ipslist, tools.Int2ip(int32(i)))
	}
	// var res []string
	if isping {
		ping_scan.CmdPing(ipslist)
	} else {
		icmp_scan.Icmp_scan2(ipslist)
	}
	sort.Slice(global.Alive_list, func(i, j int) bool {
		return tools.Ip2int(global.Alive_list[j]) > tools.Ip2int(global.Alive_list[i])
	})
	fmt.Println(global.Alive_list)
	fmt.Println(len(global.Alive_list))
	// create map ip
	// for _,ip := range global.Alive_list{
	// global.Alive_port[ip] =
	// }
	for _, ip := range global.Alive_list {
		port_scan.Socket_scan(ip)
		fmt.Println(ip, "\t->\t", global.Alive_port[ip])
	}

}

// ip := "101.43.140.240"
// laddr := get_self(ip)
// fmt.Println(laddr)
// port_scan.Raw_socket_scan(laddr, ip)

// 172.17.1.202 -> [22 2027 1062 1061 3306 5355 80 8829 8830 2026 8839 40171]
