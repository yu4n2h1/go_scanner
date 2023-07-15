package port_scan

import (
	"fmt"
	"go_scanner/global"
	"net"
	"strconv"
	"sync"
	"time"
)

func socket_conn(port int, ip string, wg *sync.WaitGroup) bool {
	wg.Add(1)
	d := &net.Dialer{Timeout: time.Duration(3) * time.Second}
	target := ip + ":" + strconv.Itoa(port)
	conn, err := d.Dial("tcp4", target)

	if err != nil {
		return false
	} else {
		defer conn.Close()
		return true
	}

}

func Socket_scan(ip string) {
	// var alive_prot []int
	var wg sync.WaitGroup
	var sub_wg sync.WaitGroup
	port_chan := make(chan int, 65536)
	alive_chan := make(chan int, 65536)
	thread_num := 800
	for i := 0; i < thread_num; i++ {
		go func() {
			for port := range port_chan {
				if socket_conn(port, ip, &sub_wg) {
					fmt.Println(ip + ":" + strconv.Itoa(port) + " is open")
					alive_chan <- port
				}
				wg.Done()
			}
		}()
	}

	go func() {
		for alive := range alive_chan {

			global.Alive_port[ip] = append(global.Alive_port[ip], alive)
			// alive_prot = append(alive_prot, alive)
			sub_wg.Done()
		}
	}()

	for i := 0; i <= 1024; i++ {
		wg.Add(1)
		port_chan <- i
	}
	for _, i := range global.Default_port {
		wg.Add(1)
		port_chan <- i
	}
	close(port_chan)

	wg.Wait()
	close(alive_chan)
	// fmt.Println(ip, "->", global.Alive_port[ip])

}
