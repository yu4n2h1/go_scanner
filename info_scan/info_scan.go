package info_scan

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"go_scanner/global"
	"io/ioutil"
	"net"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/dlclark/regexp2"
)

type VersionInfo struct {
	CPEName           string `json:"cpename"`
	DeviceType        string `json:"devicetype"`
	Hostname          string `json:"hostname"`
	Info              string `json:"info"`
	OperatingSystem   string `json:"operatingsystem"`
	VendorProductName string `json:"vendorproductname"`
	Version           string `json:"version"`
}

type Match struct {
	Pattern     string      `json:"pattern"`
	Name        string      `json:"name"`
	PatternFlag string      `json:"pattern_flag"`
	VersionInfo VersionInfo `json:"versioninfo"`
}

type JSONData struct {
	Protocol     string        `json:"protocol"`
	Probename    string        `json:"probename"`
	Probestring  string        `json:"probestring"`
	Ports        []interface{} `json:"ports"`
	SSLPorts     []interface{} `json:"sslports"`
	TotalWaitMs  string        `json:"totalwaitms"`
	TCPWrappedMs string        `json:"tcpwrappedms"`
	Rarity       string        `json:"rarity"`
	Fallback     string        `json:"fallback"`
	Matches      []Match       `json:"matches"`
}

func InfoScan(ip string, ports []int) {
	thread_num := 50
	var wg sync.WaitGroup
	port_chan := make(chan int, 100)
	for i := 0; i < thread_num; i++ {
		go func() {
			for port := range port_chan {
				// fmt.Println("Port:", port)
				startJudge(ip, port)
				wg.Done()
			}
		}()
	}

	for _, port := range ports {
		port_chan <- port
		wg.Add(1)
		// startJudge(ip, port)
	}
	wg.Wait()
}

func startJudge(ip string, port int) {
	// 读取 JSON 数据文件
	jsonData, err := ioutil.ReadFile("info_scan/finger.json")
	if err != nil {
		fmt.Println("无法读取 JSON 数据文件:", err)
		return
	}

	var dataArray []JSONData
	err = json.Unmarshal(jsonData, &dataArray)
	if err != nil {
		fmt.Println("JSON 数据解析失败:", err)
		return
	}

	// 遍历 JSON 数据
	thread_num := 11
	var wg sync.WaitGroup
	json_chan := make(chan JSONData, 11)
	// stop_chan := make(chan uint8, 1)

	for i := 0; i < thread_num; i++ {
		go func() {
			for data := range json_chan {
				probename := data.Probename
				matches := data.Matches
				probestring := data.Probestring
				// 向指定的端口发送 probename 数据
				response, err := sendProbeData(ip, port, decodeJsonData(probestring))
				// fmt.Println(response)
				if err != nil && probename == "GetRequest" {
					wg.Done()
					continue
				}

				// 判断返回数据是否与匹配模式相匹配
				for _, match := range matches {
					pattern := match.Pattern
					name := match.Name
					// vendorProductName := match.VersionInfo.VendorProductName
					// re, err := regexp.Compile(pattern)
					re := regexp2.MustCompile(pattern, 0)
					matches, _ := re.FindStringMatch(response)
					// matches := re.FindStringSubmatch(response)
					if matches != nil {
						versionInfo := match.VersionInfo
						operatingSystem := versionInfo.OperatingSystem
						deviceType := versionInfo.DeviceType
						Info := parseQuote(versionInfo.Info, matches.Groups())
						version := parseQuote(versionInfo.Version, matches.Groups())
						vendorProductName := parseQuote(versionInfo.VendorProductName, matches.Groups())
						global.Ident_server[ip][port] = [6]string{name, deviceType, Info, operatingSystem, vendorProductName, version}
					}
				}
				wg.Done()
			}
		}()
	}

	for _, data := range dataArray {
		json_chan <- data
		wg.Add(1)
	}

	wg.Wait()

}

func sendProbeData(ip string, port int, probestring string) (string, error) {
	// 构建目标地址
	target := fmt.Sprintf("%s:%d", ip, port)

	// 创建连接
	conn, err := net.DialTimeout("tcp", target, 3*time.Second)
	if err != nil {
		return "", fmt.Errorf("连接失败: %w", err)
	}
	defer conn.Close()

	// 设置发送和接收超时时间
	conn.SetDeadline(time.Now().Add(6 * time.Second))

	// 发送数据
	length := len(probestring)
	if length > 0 && probestring[length-1:] != "\n" {
		probestring = probestring + "\n"
	}

	_, err = conn.Write([]byte(probestring))
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
	// if port == 3306 && length > 6 && probestring[:6] == "GET / " {
	// 	fmt.Println(probestring)
	// 	fmt.Println(response)
	// }
	return response, nil
}

func parseQuote(version string, matches []regexp2.Group) string {
	reg := regexp.MustCompile("\\$(\\d+)")
	res := reg.FindAllStringSubmatch(version, -1)
	for i := 0; i < len(res); i++ {
		placeholder := res[i][0]
		idx, _ := strconv.Atoi(res[i][1])
		version = replaceAll(version, placeholder, matches[idx].Captures[0].String())
	}
	return version
}

func replaceAll(s, old, new string) string {
	return regexp.MustCompile(regexp.QuoteMeta(old)).ReplaceAllLiteralString(s, new)
}
func decodeJsonData(str1 string) string {
	str1 = strings.Replace(str1, "\\n", "\n", -1)
	str1 = strings.Replace(str1, "\\r", "\r", -1)
	probe := strings.Split(str1, "\\")
	if len(probe) > 1 {
		str2 := ""
		str1_length := len(str1)
		idx := 0
		for {
			if idx >= str1_length {
				break
			}
			if str1[idx] == '\\' {
				if str1[idx+1] == 'x' {
					tmp := str1[idx+2 : idx+4]
					// fmt.Println(tmp)
					str2 += tmp
					idx += 4
				} else {
					str2 += "00"
					idx += 2
				}
			} else {
				str2 += fmt.Sprintf("%x", str1[idx])
				idx += 1
			}
		}
		// fmt.Println(str2)
		str2_byte, _ := hex.DecodeString(str2)
		// fmt.Println(str2_byte)
		return string(str2_byte)
	}
	return str1
}
