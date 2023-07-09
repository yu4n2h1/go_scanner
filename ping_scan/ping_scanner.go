package ping_scan

import (
	"bytes"
	"fmt"
	"go_scanner/tools"
	"os/exec"
	"strings"
	"sync"
	"time"
)

var alive_list []string

// var mu sync.Mutex

func CmdPing(ip string, mask int) []string {
	min, max := tools.Get_ip_range(int(tools.Ip2int(ip)), mask)
	var wg sync.WaitGroup
	wg.Add(int(max-min) + 1)
	rate := 1000
	rateLimit := time.Tick(time.Second / time.Duration(rate))
	for i := min; i <= max; i++ {
		go func(ip uint32) {
			<-rateLimit
			defer wg.Done()
			addr := tools.Int2ip(int32(ip))
			ping(addr)
		}(uint32(i))
	}

	wg.Wait()
	return alive_list
}

// func wping() {
// 	// 设置要扫描的 IP 地址范围
// 	ipRange := "172.17.1."

// 	// 创建一个 WaitGroup，用于等待所有 Ping 测试的 goroutine 执行完毕
// 	var wg sync.WaitGroup
// 	wg.Add(255)

// 	// 遍历 IP 地址范围，启动 Ping 测试的 goroutine
// 	for i := 1; i <= 255; i++ {
// 		ip := ipRange + fmt.Sprintf("%d", i)
// 		go func(ip string) {
// 			ping(ip)
// 			wg.Done() // 每个 goroutine 执行完毕后递减计数器
// 		}(ip)
// 	}

// 	// 等待所有 goroutine 执行完毕
// 	wg.Wait()
// }

func ping(ip string) {
	// fmt.Println(ip)
	cmd := exec.Command("/bin/bash", "-c", "ping -c 1 -w 1 -W 100 "+ip+">/dev/null && echo true || echo false")
	var stdout, stderr bytes.Buffer
	// output := bytes.Buffer{}
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Start()
	if err != nil {
		// fmt.Println(err)
		return
	}
	if err = cmd.Wait(); err != nil {
		// fmt.Println(err)
		return
	} else {
		if strings.Contains(stdout.String(), "true") {
			fmt.Println("Hosts:", ip, "\t is alive")
			alive_list = append(alive_list, ip)
		}
	}

}
