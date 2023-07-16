package info_scan

import (
	"fmt"
	"go_scanner/honeypot_ident"
	"io/ioutil"
	"net/http"
	"regexp"
	"strings"
)

func WebInfoJudge(ip string, port int) (string, error) {
	response, err := GetWebsiteContent(ip, port)
	if err != nil {
		return "", fmt.Errorf("发生错误: %w", err)
	}
	webrules, err := GetFeatureFromFile("info_scan/webinfo.json")
	if err != nil {
		return "", fmt.Errorf("读取文件失败: %w", err)
	}

	for _, webrule := range webrules {
		matched, err := regexp.MatchString("(?i)"+webrule.Feature, response)
		if err != nil {
			return "", fmt.Errorf("发生错误: %w", err)
		}

		if matched {
			// Add honeypot detection feature
			fmt.Print(response)
			if honeypot_ident.DetectGlastopf(ip, port) {
				fmt.Println(ip, port, "may has a glastopf")
			}
			return webrule.Name, nil
		}
	}
	if honeypot_ident.DetectGlastopf(ip, port) {
		fmt.Println(ip, port, "may has a glastopf")
	}
	return "规则未命中", nil
}

func GetWebsiteContent(ip string, port int) (string, error) {
	url := fmt.Sprintf("http://%s:%d", ip, port)

	resp, err := http.Get(url)
	if err != nil {
		return "", fmt.Errorf("请求网站失败: %w", err)
	}
	defer resp.Body.Close()

	headers := resp.Header
	body, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("读取网站主体失败: %w", err)
	}

	headerStr := headersToString(headers)
	result := headerStr + string(body)
	return result, nil
}

func headersToString(headers http.Header) string {
	var builder strings.Builder

	for key, values := range headers {
		for _, value := range values {
			builder.WriteString(key + ": " + value + "\n")
		}
	}

	return builder.String()
}
