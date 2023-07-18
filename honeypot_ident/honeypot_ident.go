package honeypot_ident

import (
	"fmt"
	"go_scanner/global"
	"strconv"
	"strings"
	"time"
)

func Honeypot_ident(ip string) {
	var sshports []int = make([]int, 0)
	for _, portService := range global.Net_info[ip].Service {
		if strings.Contains(portService.Protocol, "ssh") {
			sshports = append(sshports, portService.Port)
		}
	}

	if len(sshports) >= 2 {
		for _, port := range sshports {
			if DetectKippo(ip, port) {
				global.Net_info[ip].Honeypot = append(global.Net_info[ip].Honeypot, strconv.Itoa(port)+"/"+"kippo")
			}
		}
	}

	for _, port := range global.Alive_port[ip] {
		if strings.Contains(global.Ident_server[ip][port][0], "http") {
			if DetectGlastopf(ip, port) {
				global.Net_info[ip].Honeypot = append(global.Net_info[ip].Honeypot, strconv.Itoa(port)+"/glastopf")
			}
		}
	}
	fmt.Println(4, time.Now())
	// last tasks
	isHish, HFishport := Hfish_ident(ip)
	if isHish {
		for _, port := range HFishport {
			global.Net_info[ip].Honeypot = append(global.Net_info[ip].Honeypot, strconv.Itoa(port)+"/HFish")
		}
	}
}
