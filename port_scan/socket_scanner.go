package port_scan

import (
	"fmt"
	"net"
	"strconv"
	"sync"
)

func socket_conn(port int, ip string, wg *sync.WaitGroup) bool {
	wg.Add(1)
	target := ip + ":" + strconv.Itoa(port)
	conn, err := net.Dial("tcp", target)

	if err != nil {
		return false
	} else {
		defer conn.Close()
		// fmt.Println(port, "is alive")
		return true
	}

}

func Socket_scan(ip string) {
	var alive_prot []int
	var wg sync.WaitGroup
	var sub_wg sync.WaitGroup
	lock := &sync.Mutex{}
	port_chan := make(chan int, 65536)
	alive_chan := make(chan int, 65536)
	thread_num := 10000
	is_close := false
	for i := 0; i < thread_num; i++ {
		go func() {
			wg.Add(1)
			defer wg.Done()
			for port := range port_chan {
				if socket_conn(port, ip, &sub_wg) {
					alive_chan <- port
				}
				sub_wg.Done()
			}
			sub_wg.Wait()

			lock.Lock()
			if is_close == false {
				close(alive_chan)
				is_close = true
			}
			lock.Unlock()
		}()
	}

	go func() {
		wg.Add(1)
		defer wg.Done()
		for alive := range alive_chan {
			alive_prot = append(alive_prot, alive)
		}
	}()

	for i := 0; i <= 65535; i++ {
		port_chan <- i
	}

	close(port_chan)

	wg.Wait()
	fmt.Println(ip, "->", alive_prot)
}
