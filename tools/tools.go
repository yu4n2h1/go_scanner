package tools

import (
	"bytes"
	"encoding/binary"
	"net"
	"strconv"
	"strings"

	"github.com/google/gopacket/routing"
)

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
