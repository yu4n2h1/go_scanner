package main

import (
	"encoding/json"
	"fmt"
	"go_scanner/global"
	"go_scanner/honeypot_ident"
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
	tools.Parse_Scan_port()
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
		global.Alive_port[ip] = tools.UniqueSlice(port_scan.Socket_scan(ip))
		global.Ident_server[ip] = make(map[int][6]string)
		fmt.Println(ip, "\t->\t", global.Alive_port[ip])
		global.Net_info[ip] = &global.Ip_info{}
		info_scan.InfoScan(ip, global.Alive_port[ip])
		honeypot_ident.Honeypot_ident(ip)
	}
	tools.ResFormat()
	// add test honeypot ident
	for key := range global.Net_info {
		global.Final_info[key] = *global.Net_info[key]
	}

	Final_json, err := json.MarshalIndent(global.Final_info, "", "    ")
	if err != nil {
		fmt.Println("failed!", err)
		return
	}
	fmt.Println(string(Final_json))
}
