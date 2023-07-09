package ping_scan

import (
	"bytes"
	"fmt"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

var alive_list []string

// var mu sync.Mutex

func CmdPing(ipslist []string) []string {
	OS := runtime.GOOS
	var wg sync.WaitGroup
	rate := 1000
	rateLimit := time.Tick(time.Second / time.Duration(rate))
	for _, ip := range ipslist {
		wg.Add(1)
		go func(ip string) {
			<-rateLimit
			defer wg.Done()
			addr := ip
			ping(addr, OS)
		}(ip)
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

func ping(ip, bsenv string) {
	var cmd *exec.Cmd
	if bsenv == "windows" {
		cmd = exec.Command("cmd", "/c", "ping -c 1 -w 1 "+ip+">/dev/null && echo true || echo false")
	} else if bsenv == "linux" {
		cmd = exec.Command("bash", "-c", "ping -c 1 -w 1 "+ip+">/dev/null && echo true || echo false")
	} else if bsenv == "darwin" {
		cmd = exec.Command("bash", "-c", "ping -c 1 -W 1 "+ip+">/dev/null && echo true || echo false")
	}

	// fmt.Println(ip)
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
			fmt.Println(ip, "\t is alive")
			alive_list = append(alive_list, ip)
		}
	}

}
