package info_scan

import (
	"fmt"
)

func InfoScan(ip string, ports []int) {
	for _, port := range ports {
		fmt.Println("Port:", port)
		startJudge(ip, port)
	}
}
func startJudge(ip string, port int) {
	// ip := "39.96.12.202"
	// port := 22
	serviceResult, err := ServiceJudge(ip, port)
	if err != nil {
		fmt.Println(err)
		// 进一步处理错误
	} else {
		fmt.Println("service判断结果:", serviceResult)
		// 根据判断结果进行相应操作
	}

	if serviceResult == "web" {
		webinfoResult, err := WebInfoJudge(ip, port)
		if err != nil {
			fmt.Println(err)
		} else {
			fmt.Println("web服务判断结果为: ", webinfoResult)
		}
	}
}
