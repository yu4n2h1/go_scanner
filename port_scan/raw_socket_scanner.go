package port_scan

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"go_scanner/tools"
	"math/rand"
	"net"
	"sort"
	"sync"
	"time"
)

type TCPPack struct {
	SrcPort       uint16
	DstPort       uint16
	SeqNum        uint32
	AckNum        uint32
	Flags         uint16
	Window        uint16
	ChkSum        uint16
	UrgentPointer uint16
}

func pack_tcp_request(laddr, raddr string, lport, rport uint16) []byte {
	tcpPack := TCPPack{
		SrcPort:       lport,
		DstPort:       rport,
		SeqNum:        rand.Uint32(),
		AckNum:        0,
		Flags:         0x8002,
		Window:        0xffff,
		ChkSum:        0,
		UrgentPointer: 0,
	}
	option := []byte{0x02, 0x04, 0x05, 0xb4, 0x00}
	var buffer bytes.Buffer
	binary.Write(&buffer, binary.BigEndian, tcpPack)
	binary.Write(&buffer, binary.BigEndian, option)
	binary.Write(&buffer, binary.BigEndian, [7]byte{})

	f_raw := buffer.Bytes()
	checksum := tools.Calculate_checksum(tools.Pack_tcp_pseudo_header(f_raw, tools.Ip2int(laddr), tools.Ip2int(raddr)))

	tcpPack.ChkSum = checksum
	var buffer1 bytes.Buffer
	binary.Write(&buffer1, binary.BigEndian, tcpPack)
	binary.Write(&buffer1, binary.BigEndian, option)
	binary.Write(&buffer1, binary.BigEndian, [7]byte{})
	b := buffer1.Bytes()
	// fmt.Println(lport, "->", rport, ":", tcpPack.SrcPort, "->", tcpPack.DstPort, ":", hex.EncodeToString(b))

	return b
}

func unpack_tcp_reply(tcpBytes []byte) TCPPack {
	var tcp_pack TCPPack
	buffer := bytes.NewBuffer(tcpBytes)
	binary.Read(buffer, binary.BigEndian, &tcp_pack)
	return tcp_pack
}

func random(min, max int) int {
	return rand.Intn(max-min) + min
}

func send_syn(rport uint16, laddr, raddr string, wg *sync.WaitGroup) {
	defer wg.Done()
	lport := uint16(random(10000, 65535))
	raw_tcp_byte := pack_tcp_request(laddr, raddr, (lport), (rport))
	conn, err := net.Dial("ip4:tcp", raddr) // 建立raw socket并发送数据

	if err != nil {
		fmt.Println(rport, "returned")
		return
	}

	defer conn.Close()
	if _, err := conn.Write(raw_tcp_byte); err != nil {
		// fmt.Println(err)
		return
	}
}

func recv_syn(laddr, raddr string, alive *chan uint16, stop *chan uint8) {
	listen_addr, err := net.ResolveIPAddr("ip4", laddr)
	if err != nil {
		panic(err)
	}
	conn, err := net.ListenIP("ip4:tcp", listen_addr)
	if err != nil {
		panic(err)
	}
	defer conn.Close()

	for {
		select {
		case <-*stop:
			return
		default:
			recv := make([]byte, 1024)
			// conn.SetReadDeadline(time.Now().Add(3 * time.Second))
			_, addr, err := conn.ReadFrom(recv)
			if err != nil {
				fmt.Println(err)
				continue
			}
			recv_tcp := unpack_tcp_reply(recv)

			if addr.String() != raddr || ((recv_tcp.Flags<<8)>>8) != 0x12 {
				continue
			}
			*alive <- recv_tcp.SrcPort
			// fmt.Println(recv_tcp.SrcPort, "open")

		}

	}
}

func is_element_in_list(l []int, element int) bool {
	for _, i := range l {
		if element == i {
			return true
		}
	}
	return false
}

func Raw_socket_scan(laddr, ip string) {
	port_chan := make(chan uint16, 10000)
	alive_chan := make(chan uint16, 1000)
	stop_chan := make(chan uint8, 1)
	thread_num := 1000
	rate := time.Second / 30000
	throttle := time.Tick(rate)
	var alive []int
	var wg sync.WaitGroup
	var wg_sub sync.WaitGroup
	go func() {
		recv_syn(laddr, ip, &alive_chan, &stop_chan)
	}()

	for i := 0; i <= thread_num; i++ {
		go func() {
			wg.Add(1)
			defer wg.Done()
			for port := range port_chan {
				wg_sub.Add(1)
				// fmt.Println(port)
				send_syn(port, laddr, ip, &wg_sub)
				<-throttle
			}
		}()
	}

	for i := 0; i <= 65535; i++ {
		port_chan <- uint16(i)
	}

	go func() {
		for i := range alive_chan {
			if is_element_in_list(alive, int(i)) {
				continue
			}
			alive = append(alive, int(i))
		}
	}()

	close(port_chan)
	wg.Wait()
	wg_sub.Wait()
	time.Sleep(time.Second * 1)
	fmt.Println("scan done")
	stop_chan <- 1
	close(alive_chan)
	sort.Ints(alive)
	fmt.Println(ip, "->", alive, "  ", len(alive))

}
