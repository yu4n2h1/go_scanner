package ping_scan

import (
	"bytes"
	"fmt"
	"go_scanner/global"
	"os/exec"
	"runtime"
	"strings"
	"sync"
	"time"
)

// var mu sync.Mutex

func CmdPing(ipslist []string) {
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
}

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
			global.Alive_list = append(global.Alive_list, ip)
		}

	}

}
