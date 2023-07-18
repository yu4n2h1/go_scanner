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
	if port == 443 {
		global.Ident_server[ip][port] = [6]string{"https", "", "", "", "", ""}
		return
	}
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
	http_isset := 0
	var mutex sync.Mutex
	// stop_chan := make(chan uint8, 1)

	for i := 0; i < thread_num; i++ {
		go func() {
			for data := range json_chan {
				// probename := data.Probename
				matches := data.Matches
				probestring := data.Probestring
				// 向指定的端口发送 probename 数据
				response, err := sendProbeData(ip, port, decodeJsonData(probestring))
				// fmt.Println(response)
				if err != nil {
					wg.Done()
					continue
				}
				mutex.Lock()
				if len(response) > 6 && response[:6] == "HTTP/1" && http_isset == 0 {
					global.Ident_server[ip][port] = [6]string{"http", "", "", "", "", ""}
					http_isset = 1
				}
				mutex.Unlock()
				// 判断返回数据是否与匹配模式相匹配
				for _, match := range matches {
					pattern := decodePatternData(match.Pattern)
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
						service_app := FormatResult(name, deviceType, Info, operatingSystem, vendorProductName, version)
						// global.Ident_server[ip][port] = []string{name, deviceType, Info, operatingSystem, vendorProductName, version}
						var p_s = global.Port_service{port, name, service_app}
						mutex.Lock()
						global.Net_info[ip].Service = append(global.Net_info[ip].Service, p_s)
						global.Net_info[ip].Deviceinfo = append(global.Net_info[ip].Deviceinfo, deviceType)
						mutex.Unlock()
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
func decodePatternData(str1 string) string {
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
			} else if str1[idx+1] == '0' {
				str2 += "00"
				idx += 2
			} else {
				str2 += fmt.Sprintf("%x%x", str1[idx], str1[idx+1])
				idx += 2
				// fmt.Println(str2)
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

func FormatResult(name, deviceType, Info, operatingSystem, vendorProductName, version string) []string {
	var service_app_list []string
	allResult := name + " " + deviceType + " " + Info + " " + operatingSystem + " " + vendorProductName + " " + version

	//apache
	apache_pattern := "(?i)apache(?: httpd)?\\s+([\\d.]+)"
	regex := regexp.MustCompile(apache_pattern)
	match := regex.FindStringSubmatch(allResult)
	if len(match) > 0 {
		// 版本号存在，打印匹配结果
		version := match[1]
		service_app_list = append(service_app_list, "apache/"+version)
	} else {
		// 版本号不存在
		if find := strings.Contains(strings.ToLower(allResult), strings.ToLower("apache")); find {
			service_app_list = append(service_app_list, "apache/N")
		}
	}

	ubuntu_pattern := "(?i)ubuntu\\s+([\\d.]+)"
	regex = regexp.MustCompile(ubuntu_pattern)
	match = regex.FindStringSubmatch(allResult)
	if len(match) > 0 {
		// 版本号存在，打印匹配结果
		version := match[1]
		service_app_list = append(service_app_list, "ubuntu/"+version)
	} else {
		// 版本号不存在
		if find := strings.Contains(strings.ToLower(allResult), strings.ToLower("ubuntu")); find {
			service_app_list = append(service_app_list, "ubuntu/N")
		}
	}

	debian_pattern := "(?i)debian\\s+([\\d.]+)"
	regex = regexp.MustCompile(debian_pattern)
	match = regex.FindStringSubmatch(allResult)
	if len(match) > 0 {
		// 版本号存在，打印匹配结果
		version := match[1]
		service_app_list = append(service_app_list, "debian/"+version)
	} else {
		// 版本号不存在
		if find := strings.Contains(strings.ToLower(allResult), strings.ToLower("debian")); find {
			service_app_list = append(service_app_list, "debian/N")
		}
	}

	centos_pattern := "(?i)centos\\s+([\\d.]+)"
	regex = regexp.MustCompile(centos_pattern)
	match = regex.FindStringSubmatch(allResult)
	if len(match) > 0 {
		// 版本号存在，打印匹配结果
		version := match[1]
		service_app_list = append(service_app_list, "centos/"+version)
	} else {
		// 版本号不存在
		if find := strings.Contains(strings.ToLower(allResult), strings.ToLower("centos")); find {
			service_app_list = append(service_app_list, "centos/N")
		}
	}

	windows_pattern := "(?i)windows\\s+([\\d.]+)"
	regex = regexp.MustCompile(windows_pattern)
	match = regex.FindStringSubmatch(allResult)
	if len(match) > 0 {
		// 版本号存在，打印匹配结果
		version := match[1]
		service_app_list = append(service_app_list, "windows/"+version)
	} else {
		// 版本号不存在
		if find := strings.Contains(strings.ToLower(allResult), strings.ToLower("windows")); find {
			service_app_list = append(service_app_list, "windows/N")
		}
	}

	openssh_pattern := "(?i)openssh\\s+([\\d.]+)"
	regex = regexp.MustCompile(openssh_pattern)
	match = regex.FindStringSubmatch(allResult)
	if len(match) > 0 {
		// 版本号存在，打印匹配结果
		version := match[1]
		service_app_list = append(service_app_list, "openssh/"+version)
	} else {
		// 版本号不存在
		if find := strings.Contains(strings.ToLower(allResult), strings.ToLower("openssh")); find {
			service_app_list = append(service_app_list, "openssh/N")
		}
	}

	openssl_pattern := "(?i)openssl\\s+([\\d.]+)"
	regex = regexp.MustCompile(openssl_pattern)
	match = regex.FindStringSubmatch(allResult)
	if len(match) > 0 {
		// 版本号存在，打印匹配结果
		version := match[1]
		service_app_list = append(service_app_list, "openssl/"+version)
	} else {
		// 版本号不存在
		if find := strings.Contains(strings.ToLower(allResult), strings.ToLower("openssl")); find {
			service_app_list = append(service_app_list, "openssl/N")
		}
	}

	LiteSpeed_pattern := "(?i)LiteSpeed(?: httpd)?\\s+([\\d.]+)"
	regex = regexp.MustCompile(LiteSpeed_pattern)
	match = regex.FindStringSubmatch(allResult)
	if len(match) > 0 {
		// 版本号存在，打印匹配结果
		version := match[1]
		service_app_list = append(service_app_list, "LiteSpeed/"+version)
	} else {
		// 版本号不存在
		if find := strings.Contains(strings.ToLower(allResult), strings.ToLower("LiteSpeed")); find {
			service_app_list = append(service_app_list, "LiteSpeed/N")
		}
	}

	Jetty_pattern := "(?i)Jetty\\s+([\\d.]+)"
	regex = regexp.MustCompile(Jetty_pattern)
	match = regex.FindStringSubmatch(allResult)
	if len(match) > 0 {
		// 版本号存在，打印匹配结果
		version := match[1]
		service_app_list = append(service_app_list, "Jetty/"+version)
	} else {
		// 版本号不存在
		if find := strings.Contains(strings.ToLower(allResult), strings.ToLower("Jetty")); find {
			service_app_list = append(service_app_list, "Jetty/N")
		}
	}

	java_pattern := "(?i)java\\s+([\\d.]+)"
	regex = regexp.MustCompile(java_pattern)
	match = regex.FindStringSubmatch(allResult)
	if len(match) > 0 {
		// 版本号存在，打印匹配结果
		version := match[1]
		service_app_list = append(service_app_list, "java/"+version)
	} else {
		// 版本号不存在
		if find := strings.Contains(strings.ToLower(allResult), strings.ToLower("java")); find {
			service_app_list = append(service_app_list, "java/N")
		}
	}

	nodejs_pattern := "(?i)node\\.js(?: httpd)?\\s+([\\d.]+)"
	regex = regexp.MustCompile(nodejs_pattern)
	match = regex.FindStringSubmatch(allResult)
	if len(match) > 0 {
		// 版本号存在，打印匹配结果
		version := match[1]
		service_app_list = append(service_app_list, "node.js/"+version)
	} else {
		// 版本号不存在
		if find := strings.Contains(strings.ToLower(allResult), strings.ToLower("node.js")); find {
			service_app_list = append(service_app_list, "node.js/N")
		}
	}

	express_pattern := "(?i)express\\s+([\\d.]+)"
	regex = regexp.MustCompile(express_pattern)
	match = regex.FindStringSubmatch(allResult)
	if len(match) > 0 {
		// 版本号存在，打印匹配结果
		version := match[1]
		service_app_list = append(service_app_list, "express/"+version)
	} else {
		// 版本号不存在
		if find := strings.Contains(strings.ToLower(allResult), strings.ToLower("express")); find {
			service_app_list = append(service_app_list, "express/N")
		}
	}

	asp_pattern := "(?i)asp.net\\s+([\\d.]+)"
	regex = regexp.MustCompile(asp_pattern)
	match = regex.FindStringSubmatch(allResult)
	if len(match) > 0 {
		// 版本号存在，打印匹配结果
		version := match[1]
		service_app_list = append(service_app_list, "asp.net/"+version)
	} else {
		// 版本号不存在
		if find := strings.Contains(strings.ToLower(allResult), strings.ToLower("asp.net")); find {
			service_app_list = append(service_app_list, "asp.net/N")
		}
	}

	php_pattern := "(?i)php\\s+([\\d.]+)"
	regex = regexp.MustCompile(php_pattern)
	match = regex.FindStringSubmatch(allResult)
	if len(match) > 0 {
		// 版本号存在，打印匹配结果
		version := match[1]
		service_app_list = append(service_app_list, "php/"+version)
	} else {
		// 版本号不存在
		if find := strings.Contains(strings.ToLower(allResult), strings.ToLower("php")); find {
			service_app_list = append(service_app_list, "php/N")
		}
	}

	Microsoft_HTTPAPI_pattern := "(?i)Microsoft HTTPAPI httpd\\s+([\\d.]+)"
	regex = regexp.MustCompile(Microsoft_HTTPAPI_pattern)
	match = regex.FindStringSubmatch(allResult)
	if len(match) > 0 {
		// 版本号存在，打印匹配结果
		version := match[1]
		service_app_list = append(service_app_list, "Microsoft-HTTPAPI/"+version)
	} else {
		// 版本号不存在
		if find := strings.Contains(strings.ToLower(allResult), strings.ToLower("Microsoft-HTTPAPI")); find {
			service_app_list = append(service_app_list, "Microsoft-HTTPAPI/N")
		}
	}

	RabbitMQ_pattern := "(?i)RabbitMQ\\s+([\\d.]+)"
	regex = regexp.MustCompile(RabbitMQ_pattern)
	match = regex.FindStringSubmatch(allResult)
	if len(match) > 0 {
		// 版本号存在，打印匹配结果
		version := match[1]
		service_app_list = append(service_app_list, "RabbitMQ/"+version)
	} else {
		// 版本号不存在
		if find := strings.Contains(strings.ToLower(allResult), strings.ToLower("RabbitMQ")); find {
			service_app_list = append(service_app_list, "RabbitMQ/N")
		}
	}

	iis_pattern := "(?i)iis(?: httpd)?(?: ftpd)?(?: WebDAV)?\\s+([\\d.]+)"
	regex = regexp.MustCompile(iis_pattern)
	match = regex.FindStringSubmatch(allResult)
	if len(match) > 0 {
		// 版本号存在，打印匹配结果
		version := match[1]
		service_app_list = append(service_app_list, "iis/"+version)
	} else {
		// 版本号不存在
		if find := strings.Contains(strings.ToLower(allResult), strings.ToLower("iis")); find {
			service_app_list = append(service_app_list, "iis/N")
		}
	}

	nginx_pattern := "(?i)nginx\\s+([\\d.]+)"
	regex = regexp.MustCompile(nginx_pattern)
	match = regex.FindStringSubmatch(allResult)
	if len(match) > 0 {
		// 版本号存在，打印匹配结果
		version := match[1]
		service_app_list = append(service_app_list, "nginx/"+version)
	} else {
		// 版本号不存在
		if find := strings.Contains(strings.ToLower(allResult), strings.ToLower("nginx")); find {
			service_app_list = append(service_app_list, "nginx/N")
		}
	}

	micro_httpd_pattern := "(?i)micro_httpd\\s+([\\d.]+)"
	regex = regexp.MustCompile(micro_httpd_pattern)
	match = regex.FindStringSubmatch(allResult)
	if len(match) > 0 {
		// 版本号存在，打印匹配结果
		version := match[1]
		service_app_list = append(service_app_list, "micro_httpd/"+version)
	} else {
		// 版本号不存在
		if find := strings.Contains(strings.ToLower(allResult), strings.ToLower("micro_httpd")); find {
			service_app_list = append(service_app_list, "micro_httpd/N")
		}
	}

	openresty_pattern := "(?i)OpenResty web app server\\s+([\\d.]+)"
	regex = regexp.MustCompile(openresty_pattern)
	match = regex.FindStringSubmatch(allResult)
	if len(match) > 0 {
		// 版本号存在，打印匹配结果
		version := match[1]
		service_app_list = append(service_app_list, "openresty/"+version)
	} else {
		// 版本号不存在
		if find := strings.Contains(strings.ToLower(allResult), strings.ToLower("openresty")); find {
			service_app_list = append(service_app_list, "openresty/N")
		}
	}

	grafana_pattern := "(?i)grafana\\s+([\\d.]+)"
	regex = regexp.MustCompile(grafana_pattern)
	match = regex.FindStringSubmatch(allResult)
	if len(match) > 0 {
		// 版本号存在，打印匹配结果
		version := match[1]
		service_app_list = append(service_app_list, "grafana/"+version)
	} else {
		// 版本号不存在
		if find := strings.Contains(strings.ToLower(allResult), strings.ToLower("grafana")); find {
			service_app_list = append(service_app_list, "grafana/N")
		}
	}

	Weblogic_pattern := "(?i)WebLogic(?: applications server)?(?: httpd)?(?: Server)?\\s+([\\d.]+)"
	regex = regexp.MustCompile(Weblogic_pattern)
	match = regex.FindStringSubmatch(allResult)
	if len(match) > 0 {
		// 版本号存在，打印匹配结果
		version := match[1]
		service_app_list = append(service_app_list, "Weblogic/"+version)
	} else {
		// 版本号不存在
		if find := strings.Contains(strings.ToLower(allResult), strings.ToLower("Weblogic")); find {
			service_app_list = append(service_app_list, "Weblogic/N")
		}
	}

	fmt.Println(service_app_list)
	return service_app_list
}
