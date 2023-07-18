package honeypot_ident

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

func connect_to_ssh(ip string, port int, sendbyte []byte) string {
	conn, err := net.DialTimeout("tcp", ip+":"+strconv.Itoa(port), 3*time.Second)
	if err != nil {
		return "aa1"
	}
	buf := make([]byte, 1024)
	_, err = conn.Read(buf)
	if err != nil {
		return "bb2"
	}
	_, err = conn.Write(sendbyte)
	responseBuf := make([]byte, 1024)
	_, err = conn.Read(responseBuf)
	if err != nil {
		return "cc3"
	}
	conn.Close()
	var response string = string(responseBuf)
	return response
}

func DetectKippo(ip string, port int) bool {
	// if connect_to_ssh(ip, port ,)
	var score int = 0
	var response string = connect_to_ssh(ip, port, []byte("SSH-1337\n"))
	fmt.Println(response)
	if strings.Contains(response, "bad version") {
		score += 1
	}

	response = connect_to_ssh(ip, port, []byte("\n\n\n\n\n\n\n\n"))
	fmt.Println(response)
	if strings.Contains(response, "168430090") {
		score += 1
	}
	fmt.Println(ip, port, score)
	if score >= 1 {
		return true
	}
	return false
}
