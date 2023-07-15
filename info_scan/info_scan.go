package info_scan

import (
	"encoding/json"
	"fmt"
	"go_scanner/honeypot_ident"
	"io/ioutil"
	"net"
	"regexp"
	"strings"
	"time"
)

type Service struct {
	Name    string `json:"name"`
	Feature string `json:"feature"`
}

func getPortInfo(ip string, port int) (string, error) {
	// 构建目标地址
	target := fmt.Sprintf("%s:%d", ip, port)

	// 创建连接
	conn, err := net.DialTimeout("tcp", target, 3*time.Second)
	if err != nil {
		return "", fmt.Errorf("连接失败: %w", err)
	}
	defer conn.Close()

	// 设置发送和接收超时时间
	conn.SetDeadline(time.Now().Add(3 * time.Second))

	// 发送数据
	_, err = conn.Write([]byte("7f519f7fa3eec7c5e3049a681c62f9f9\n"))
	if err != nil {
		return "", fmt.Errorf("发送数据失败: %w", err)
	}

	// 接收响应
	buffer := make([]byte, 1024)
	n, err := conn.Read(buffer)
	if err != nil {
		return "", fmt.Errorf("接收数据失败: %w", err)
	}

	response := string(buffer[:n])
	return response, nil
}

func ServiceJudge(ip string, port int) (string, error) {
	response, err := getPortInfo(ip, port)
	if err != nil {
		return "", fmt.Errorf("发生错误: %w", err)
	}

	services, err := GetFeatureFromFile("info_scan/service.json")
	if err != nil {
		return "", fmt.Errorf("读取文件失败: %w", err)
	}

	for _, service := range services {
		matched, err := regexp.MatchString("(?i)"+service.Feature, response)
		if err != nil {
			return "", fmt.Errorf("发生错误: %w", err)
		}
		if matched {
			if strings.Contains(service.Name, "ssh") {
				// honeypot_ident.DetectKippo()
				if honeypot_ident.DetectKippo(ip, port) {
					fmt.Println(service.Name, "may is Kippo")
				}
			}
			return service.Name, nil
		}
	}
	return "规则未命中", nil
}

func GetFeatureFromFile(filename string) ([]Service, error) {
	jsonData, err := ioutil.ReadFile(filename)
	if err != nil {
		return nil, fmt.Errorf("读取 JSON 文件失败: %w", err)
	}

	var services []Service
	err = json.Unmarshal(jsonData, &services)
	if err != nil {
		return nil, fmt.Errorf("解析 JSON 数据失败: %w", err)
	}

	return services, nil
}
