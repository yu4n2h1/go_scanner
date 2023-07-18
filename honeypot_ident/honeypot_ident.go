package honeypot_ident

import (
	"fmt"
	"go_scanner/global"
	"strconv"
	"strings"
	"sync"
)

func Honeypot_ident(ip string) {
	var sshports []int = make([]int, 0)
	for _, portService := range global.Net_info[ip].Service {
		if strings.Contains(portService.Protocol, "ssh") {
			sshports = append(sshports, portService.Port)
		}
	}
	var wg sync.WaitGroup
	var mutex sync.Mutex

	if len(sshports) >= 2 {
		for _, port := range sshports {
			fmt.Println(strconv.Itoa(port) + "start!!!")
			wg.Add(1)
			go func(port int) {
				defer wg.Done()
				if DetectKippo(ip, port) {
					mutex.Lock()
					global.Net_info[ip].Honeypot = append(global.Net_info[ip].Honeypot, strconv.Itoa(port)+"/"+"kippo")
					mutex.Unlock()
				}
				fmt.Println(strconv.Itoa(port) + "finish!!!")

			}(port)
		}
	}

	for _, port := range global.Alive_port[ip] {
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			if strings.Contains(global.Ident_server[ip][port][0], "http") {
				if DetectGlastopf(ip, port) {
					mutex.Lock()
					global.Net_info[ip].Honeypot = append(global.Net_info[ip].Honeypot, strconv.Itoa(port)+"/glastopf")
					mutex.Unlock()
				}
			}
		}(port)
	}
	// fmt.Println(4, time.Now())
	// last tasks
	isHish, HFishport := Hfish_ident(ip)
	if isHish {
		for _, port := range HFishport {
			global.Net_info[ip].Honeypot = append(global.Net_info[ip].Honeypot, strconv.Itoa(port)+"/HFish")
		}
		global.Net_info[ip].Honeypot = append(global.Net_info[ip].Honeypot, "4433/HFish")
		global.Net_info[ip].Honeypot = append(global.Net_info[ip].Honeypot, "4434/HFish")

	}
	wg.Wait()
}
