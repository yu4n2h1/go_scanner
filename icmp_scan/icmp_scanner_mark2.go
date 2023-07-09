package icmp_scan

import (
	"fmt"
	"go_scanner/tools"
	"net"
	"sync"
	"time"

	"golang.org/x/net/icmp"
)

func is_element_in_list(l []string, element string) bool {
	for _, i := range l {
		if element == i {
			return true
		}
	}
	return false
}
func Icmp_scan2(ipslist []string) []string {
	conn, err := icmp.ListenPacket("ip4:icmp", "0.0.0.0")
	if err != nil {
		panic(err)
	}
	stop_chan := make(chan uint8, 1)
	alive_chan := make(chan string, 65536)
	var wg sync.WaitGroup
	go func() {
		for {
			select {
			case <-stop_chan:
				return
			default:
				recv := make([]byte, 1024)
				_, addr, _ := conn.ReadFrom(recv)
				if addr != nil {
					// fmt.Println(addr)
					wg.Add(1)
					alive_chan <- addr.String()
				}
			}
		}
	}()

	for _, ip := range ipslist {
		dst, _ := net.ResolveIPAddr("ip", ip)
		// fmt.Println(dst)
		IcmpByte := Make_icmp_pack(uint16(tools.Ip2int(ip)))
		conn.WriteTo(IcmpByte, dst)
	}

	go func() {
		for alive := range alive_chan {
			if !is_element_in_list(alive_list, alive) && is_element_in_list(ipslist, alive) {
				fmt.Println(alive, "\tis alive")
				alive_list = append(alive_list, alive)
			}
			wg.Done()
		}
	}()
	if len(ipslist) >= 156 {
		time.Sleep(time.Duration(6) * time.Second)
	} else {
		time.Sleep(time.Duration(3) * time.Second)
	}
	stop_chan <- 1
	wg.Wait()
	close(alive_chan)
	conn.Close()
	return alive_list
}
