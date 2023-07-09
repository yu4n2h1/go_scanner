package main

import (
	"flag"
	"fmt"
	"go_scanner/icmp_scan"
	"go_scanner/ping_scan"
	"go_scanner/port_scan"
)

func main() {
	raddr := flag.String("i", "127.0.0.1", "Input the ip address you want to scan")
	mask := flag.Int("m", 31, "Input the mask of target network")
	pingis := flag.Bool("ping", false, "Input the ping ro not")
	flag.Parse()

	// laddr := tools.Get_self(*raddr)
	if *pingis {
		fmt.Println("使用ping")
		res := ping_scan.CmdPing(*raddr, *mask)
		fmt.Println(res)
		fmt.Println(len(res))
	} else {
		res := icmp_scan.Ping(*raddr, *mask)
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
}

// 172.17.1.202 -> [22 2027 1062 1061 3306 5355 80 8829 8830 2026 8839 40171]
