package main

import (
	"fmt"
	"go_scanner/global"
	"go_scanner/icmp_scan"
	"go_scanner/info_scan"
	"go_scanner/ping_scan"
	"go_scanner/port_scan"
	"go_scanner/tools"
	"sort"
)

func main() {
	tools.Parse_flag()
	ipslist := tools.Parse_IP()
	var isping bool = *global.Pingis
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
	for _, ip := range global.Alive_list {
		port_scan.Socket_scan(ip)
		fmt.Println(ip, "\t->\t", global.Alive_port[ip])
		info_scan.InfoScan(ip, global.Alive_port[ip])
	}

}
