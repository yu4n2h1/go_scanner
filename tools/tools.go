package tools

import (
	"bytes"
	"encoding/binary"
	"flag"
	"fmt"
	"go_scanner/global"
	"net"
	"strconv"
	"strings"

	"github.com/google/gopacket/routing"
)

func Parse_flag() {
	global.CIDR = flag.String("h", "127.0.0.1/32", "Scan IP addresses based on input in CIDR notation.")
	global.Pingis = flag.Bool("ping", false, "Input the ping ro not")
	global.Portstring = flag.String("p", "", "Input the ports to be scanned.")
	flag.Parse()
}

// to set the ports to be scanned
func Parse_Scan_port() {
	if *global.Portstring == "" {
		global.Default_port = []int{1080, 1081, 1082, 1099, 1118, 1433, 1521, 1888, 2008, 2020, 2100, 2222, 2375, 2379, 3000, 3008, 3128, 3306, 3505, 5432, 5555, 6080, 6379, 6648, 6868, 7000, 7001, 7002, 7003, 7004, 7005, 7007, 7008, 7070, 7071, 7074, 7078, 7080, 7088, 7200, 7680, 7687, 7688, 7777, 7890, 8000, 8001, 8002, 8003, 8004, 8006, 8008, 8009, 8010, 8011, 8012, 8016, 8018, 8020, 8028, 8030, 8038, 8042, 8044, 8046, 8048, 8053, 8060, 8069, 8070, 8080, 8081, 8082, 8083, 8084, 8085, 8086, 8087, 8088, 8089, 8090, 8091, 8092, 8093, 8094, 8095, 8096, 8097, 8098, 8099, 8100, 8101, 8108, 8118, 8161, 8172, 8180, 8181, 8200, 8222, 8244, 8258, 8280, 8288, 8300, 8360, 8443, 8448, 8484, 8800, 8834, 8838, 8848, 8858, 8868, 8879, 8880, 8881, 8888, 8899, 8983, 8989, 9000, 9001, 9002, 9008, 9010, 9043, 9060, 9080, 9081, 9082, 9083, 9084, 9085, 9086, 9087, 9088, 9089, 9090, 9091, 9092, 9093, 9094, 9095, 9096, 9097, 9098, 9099, 9100, 9200, 9443, 9448, 9800, 9981, 9986, 9988, 9998, 9999, 10000, 10001, 10002, 10004, 10008, 10010, 10250, 11211, 12018, 12443, 14000, 16080, 18000, 18001, 18002, 18004, 18008, 18080, 18082, 18088, 18090, 18098, 19001, 20000, 20720, 20880, 21000, 21501, 21502, 27017, 28018, 37777}
		return
	}
	for _, ports_string := range strings.Split(*global.Portstring, ",") {
		var err error
		if strings.Contains(ports_string, "-") {
			args := strings.Split(ports_string, "-")
			if len(args) != 2 {
				panic("Please enter a string with the correct format for port numbers.")
			}
			var err error
			var portstart int
			portstart, err = strconv.Atoi(args[0])
			if err != nil {
				panic("Please enter a string with the correct format for port numbers.")
			}

			// var err error
			var portend int
			portend, err = strconv.Atoi(args[1])
			if err != nil {
				panic("Please enter a string with the correct format for port numbers.")
			}
			if portstart > portend {
				panic("Please enter a string with the correct format for port numbers.")

			}

			for port := portstart; port <= portend; port++ {
				global.Default_port = append(global.Default_port, port)
			}

		} else {
			var portInt int
			portInt, err = strconv.Atoi(ports_string)
			if err == nil {
				global.Default_port = append(global.Default_port, portInt)
			} else {
				// deal with error
			}
		}
	}

	// return global.Default_port
}

func Parse_IP() []string {
	var err error
	if strings.Contains(*global.CIDR, "/") {
		args := strings.Split(*global.CIDR, "/")
		if len(args) != 2 {
			panic("please input the string with CIDR")
		}
		global.Raddr = args[0]
		global.Mask, err = strconv.Atoi(args[1])
	} else {
		global.Mask = 32
		global.Raddr = *global.CIDR
	}
	if err != nil {
		fmt.Println(err)
		return nil
	}
	min, max := Get_ip_range(int(Ip2int(global.Raddr)), global.Mask)
	ipslist := make([]string, max-min)
	for i := min; i <= max; i++ {
		ipslist = append(ipslist, Int2ip(int32(i)))
	}
	return ipslist
}

func Get_self(raddr string) string {
	ip := net.ParseIP(raddr)
	router, err := routing.New()
	if err != nil {
		panic(err)
	}
	_, _, src, err := router.Route(ip)
	// fmt.Println(inface.Name, gw, src)
	if err != nil {
		panic(err)
	}
	return src.String()
}

func bytes_sum(b []byte) int {
	var sum int
	for _, value := range b {
		sum += int(value)
	}
	return sum
}
func Pack_tcp_pseudo_header(data []byte, laddr, raddr int32) []byte {
	var buffer bytes.Buffer
	binary.Write(&buffer, binary.BigEndian, laddr)
	binary.Write(&buffer, binary.BigEndian, raddr)
	binary.Write(&buffer, binary.BigEndian, []byte{0, 6, 0}) // zeros、protocol
	binary.Write(&buffer, binary.BigEndian, byte(len(data)))
	pseudoHeader := buffer.Bytes()
	length := len(pseudoHeader) + len(data)
	if length%2 != 0 { // 不是2的倍数
		length++
	}
	target := make([]byte, 0, length)
	target = append(target, pseudoHeader...)
	target = append(target, data...)
	return target
}

func Calculate_checksum(pack []byte) uint16 {
	var high []byte
	var low []byte
	for idx, value := range pack {
		if idx&1 == 1 {
			low = append(low, value)
		} else {
			high = append(high, value)
		}
	}
	checksum := ((bytes_sum(high) << 8) + bytes_sum(low))

	for rest := checksum >> 16; rest != 0; {
		checksum = checksum&0xffff + rest
		rest = checksum >> 16
	}

	final_checksum := uint16(^checksum & 0xffff)
	return final_checksum
}

func Ip2int(ip string) int32 {
	tmp := strings.Split(ip, ".")
	var sum int32
	for idx, value := range tmp {
		num, _ := strconv.Atoi(value)
		sum += int32(num) << ((3 - idx) * 8)
	}

	return sum
}

func Int2ip(ip int32) string {
	part1 := strconv.Itoa(int(ip) & 0xff)
	part2 := strconv.Itoa((int(ip) & 0xff00) >> 8)
	part3 := strconv.Itoa((int(ip) & 0xff0000) >> 16)
	part4 := strconv.Itoa((int(ip) & 0xff000000) >> 24)
	ret_value := part4 + "." + part3 + "." + part2 + "." + part1
	return ret_value
}

func Get_ip_range(ip, mask int) (int, int) {
	tmp_mask := ((1 << mask) - 1) << (32 - mask)
	// fmt.Printf("%x\n", tmp_mask)
	min_ip := ip & tmp_mask
	max_ip := min_ip + (^tmp_mask & 0xffffffff)
	return min_ip, max_ip
}

func UniqueSlice(slice []int) []int {
	seen := make(map[int]bool)
	result := []int{}
	for _, value := range slice {
		if _, ok := seen[value]; !ok {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}
func UniqueSliceString(slice []string) []string {
	seen := make(map[string]bool)
	result := []string{}
	for _, value := range slice {
		if _, ok := seen[value]; !ok {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}
func IsPortIn(ip string, port int) bool {
	for _, s := range global.Net_info[ip].Service {
		if port == s.Port {
			return true
		}
	}
	return false
}
func FindPortIn(ip string, port int) *global.Port_service {
	length := len(global.Net_info[ip].Service)
	for i := 0; i < length; i++ {
		if global.Net_info[ip].Service[i].Port == port {
			return &global.Net_info[ip].Service[i]
		}
	}
	return nil
}
func ResFormat() {
	for _, ip := range global.Alive_list {
		//Deviceinfo
		global.Net_info[ip].Deviceinfo = UniqueSliceString(global.Net_info[ip].Deviceinfo)
		if (len(global.Net_info[ip].Deviceinfo) == 1 && global.Net_info[ip].Deviceinfo[0] == "") || len(global.Net_info[ip].Deviceinfo) == 0 {
			global.Net_info[ip].Deviceinfo = nil
		}
		//http https
		for _, port := range global.Alive_port[ip] {
			if len(global.Ident_server[ip][port][0]) >= 4 && global.Ident_server[ip][port][0][:4] == "http" && !IsPortIn(ip, port) {
				var p_s = global.Port_service{port, global.Ident_server[ip][port][0], nil}
				global.Net_info[ip].Service = append(global.Net_info[ip].Service, p_s)
			}
		}
		//null server
		for _, port := range global.Alive_port[ip] {
			if !IsPortIn(ip, port) {
				var p_s global.Port_service
				p_s.Port = port
				global.Net_info[ip].Service = append(global.Net_info[ip].Service, p_s)
			}
		}
	}

}
