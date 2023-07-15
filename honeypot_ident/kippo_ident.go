package honeypot_ident

import (
	"fmt"
	"net"
	"strconv"
	"strings"
	"time"
)

func DetectKippo(ip string, port int) bool {
	conn, err := net.DialTimeout("tcp", ip+":"+strconv.Itoa(port), 3*time.Second)
	if err != nil {
		panic(err)
	}
	buf := make([]byte, 1024)
	_, err = conn.Read(buf)
	if err != nil {
		panic(err)
	}

	_, err = conn.Write([]byte("\n\n\n\n\n\n\n\n"))
	if err != nil {
		panic(err)
	}
	responseBuf := make([]byte, 1024)
	_, err = conn.Read(responseBuf)
	if err != nil {
		panic(err)
	}
	response := string(responseBuf)
	conn.Close()
	if strings.Contains(response, "168430090") {
		fmt.Println("Kippo is on", ip, port)
		return true
	}
	fmt.Println("debug")
	return false
}
