package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"regexp"
	"runtime"
	"strconv"
	"strings"
)

// Define holders for the cli arguments we wish to parse.
type selfFlags struct {
	BroadcastInterface, BroadcastIP, UDPPort string
}

const (
	Ldate         = 1 << iota                     //日期示例： 2009/01/23
	Ltime                                         //时间示例: 01:23:23
	Lmicroseconds                                 //毫秒示例: 01:23:23.123123.
	LstdFlags     = Ldate | Ltime | Lmicroseconds //Go提供的标准抬头信息
)

var (
	delims   = ":-"
	reMAC    = regexp.MustCompile(`^([0-9a-fA-F]{2}[` + delims + `]){5}([0-9a-fA-F]{2})$`)
	cliFlags selfFlags
	err      error
	debugLog *log.Logger
)

// ipFromInterface returns a `*net.UDPAddr` from a network interface name.
//func ipFromInterface(iface string) (*net.UDPAddr, error) {
//	ief, err := net.InterfaceByName(iface)
//	if err != nil {
//		return nil, err
//	}
//
//	addrs, err := ief.Addrs()
//	if err == nil && len(addrs) <= 0 {
//		err = fmt.Errorf("no address associated with interface %s", iface)
//	}
//	if err != nil {
//		return nil, err
//	}
//
//	// Validate that one of the addrs is a valid network IP address.
//	for _, addr := range addrs {
//		switch ip := addr.(type) {
//		case *net.IPNet:
//			// Verify that the DefaultMask for the address we want to use exists.
//			if ip.IP.DefaultMask() != nil {
//				return &net.UDPAddr{
//					IP: ip.IP,
//				}, nil
//			}
//		}
//	}
//	return nil, fmt.Errorf("no address associated with interface %s", iface)
//}

// MACAddress represents a 6 byte network mac address.
type MACAddress [6]byte

// A MagicPacket is constituted of 6 bytes of 0xFF followed by 16-groups of the destination MAC address.
type MagicPacket struct {
	header  [6]byte
	payload [16]MACAddress
}

// New returns a magic packet based on a mac address string.
func New(mac string) (*MagicPacket, error) {
	var packet MagicPacket
	var macAddr MACAddress

	hwAddr, err := net.ParseMAC(mac)
	if err != nil {
		debugLog.Printf("ParseMAC error: %s\n", err)
		return nil, err
	}

	// We only support 6 byte MAC addresses since it is much harder to use the
	// binary.Write(...) interface when the size of the MagicPacket is dynamic.
	if !reMAC.MatchString(mac) {
		debugLog.Printf("%s is not a IEEE 802 MAC-48 address\n", mac)
		return nil, fmt.Errorf("%s is not a IEEE 802 MAC-48 address", mac)
	}

	// Copy bytes from the returned HardwareAddr -> a fixed size MACAddress.
	for idx := range macAddr {
		macAddr[idx] = hwAddr[idx]
	}

	// Setup the header which is 6 repetitions of 0xFF.
	for idx := range packet.header {
		packet.header[idx] = 0xFF
	}

	// Setup the payload which is 16 repetitions of the MAC addr.
	for idx := range packet.payload {
		packet.payload[idx] = macAddr
	}

	return &packet, nil
}

// Marshal serializes the magic packet structure into a 102 byte slice.
func (mp *MagicPacket) Marshal() ([]byte, error) {
	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.BigEndian, mp); err != nil {
		return nil, err
	}

	return buf.Bytes(), nil
}

// Run the wake command.
func wakeCmd(args []string) error {
	// bcastInterface can be "eth0", "eth1", etc.. An empty string implies
	// that we use the default interface when sending the UDP packet (nil).
	macAddr := args[0]
	cliFlags.BroadcastInterface = ""
	//bcastInterface := ""

	if "" == args[1] {
		cliFlags.BroadcastIP = "255.255.255.255"
	} else {
		cliFlags.BroadcastIP = args[1]
	}
	cliFlags.UDPPort = "9"

	// Always use the interface specified in the command line, if it exists.
	//if cliFlags.BroadcastInterface != "" {
	//	bcastInterface = cliFlags.BroadcastInterface
	//}

	// Populate the local address in the event that the broadcast interface has been set.
	var localAddr *net.UDPAddr
	//if bcastInterface != "" {
	//	localAddr, err = ipFromInterface(bcastInterface)
	//	if err != nil {
	//		return err
	//	}
	//}

	// The address to broadcast to is usually the default `255.255.255.255` but
	// can be overloaded by specifying an override in the CLI arguments.
	bcastAddr := fmt.Sprintf("%s:%s", cliFlags.BroadcastIP, cliFlags.UDPPort)
	udpAddr, err := net.ResolveUDPAddr("udp", bcastAddr)
	if err != nil {
		return err
	}

	// Build the magic packet.
	mp, err := New(macAddr)
	if err != nil {
		return err
	}

	// Grab a stream of bytes to send.
	bs, err := mp.Marshal()
	if err != nil {
		return err
	}

	// Grab a UDP connection to send our packet of bytes.
	conn, err := net.DialUDP("udp", localAddr, udpAddr)
	if err != nil {
		return err
	}
	defer conn.Close()

	debugLog.Printf("Attempting to send a magic packet to MAC: %s\n", macAddr)
	debugLog.Printf("........................ Broadcasting to: %s\n", bcastAddr)
	debugLog.Printf("............................ udpAddr is : %s\n", udpAddr)
	n, err := conn.Write(bs)
	if err == nil && n != 102 {
		err = fmt.Errorf("magic packet sent was %d bytes (expected 102 bytes sent)", n)
		debugLog.Printf("magic packet sent was %d bytes (expected 102 bytes sent)\n", n)
	}
	if err != nil {
		return err
	}

	debugLog.Printf("Magic packet sent successfully to MAC: %s\n", macAddr)
	return nil
}

type Ip struct {
	ip          string
	networkSize int
	subnet_mask int
}

func convertQuardsToInt(splits []string) []int {
	quardsInt := []int{}
	for _, quard := range splits {
		j, err := strconv.Atoi(quard)
		if err != nil {
			panic(err)
		}
		quardsInt = append(quardsInt, j)
	}
	return quardsInt
}

func (s *Ip) GetIPAddressQuads() []int {
	splits := strings.Split(s.ip, ".")
	return convertQuardsToInt(splits)
}

func (s *Ip) networkCalculation(format, separator string) string {
	splits := s.GetIPAddressQuads()
	networkQuards := []string{}
	networkQuards = append(networkQuards, fmt.Sprintf(format, splits[0]&(s.subnet_mask>>24)))
	networkQuards = append(networkQuards, fmt.Sprintf(format, splits[1]&(s.subnet_mask>>16)))
	networkQuards = append(networkQuards, fmt.Sprintf(format, splits[2]&(s.subnet_mask>>8)))
	networkQuards = append(networkQuards, fmt.Sprintf(format, splits[3]&(s.subnet_mask>>0)))
	return strings.Join(networkQuards, separator)
}

func (s *Ip) GetNetworkPortionQuards() []int {
	return convertQuardsToInt(strings.Split(s.networkCalculation("%d", "."), "."))
}

func (s *Ip) GetNumberIPAddresses() int {
	return 2 << uint(31-s.networkSize)
}

func (s *Ip) GetBroadcastAddress() string {
	networkQuads := s.GetNetworkPortionQuards()
	numberIPAddress := s.GetNumberIPAddresses()
	networkRangeQuads := []string{}
	networkRangeQuads = append(networkRangeQuads, fmt.Sprintf("%d", (networkQuads[0]&(s.subnet_mask>>24))+(((numberIPAddress-1)>>24)&0xFF)))
	networkRangeQuads = append(networkRangeQuads, fmt.Sprintf("%d", (networkQuads[1]&(s.subnet_mask>>16))+(((numberIPAddress-1)>>16)&0xFF)))
	networkRangeQuads = append(networkRangeQuads, fmt.Sprintf("%d", (networkQuads[2]&(s.subnet_mask>>8))+(((numberIPAddress-1)>>8)&0xFF)))
	networkRangeQuads = append(networkRangeQuads, fmt.Sprintf("%d", (networkQuads[3]&(s.subnet_mask>>0))+(((numberIPAddress-1)>>0)&0xFF)))
	return strings.Join(networkRangeQuads, ".")
}

func SubnetCalculator(ip string, networkSize int) *Ip {

	s := &Ip{
		ip:          ip,
		networkSize: networkSize,
		subnet_mask: 0xFFFFFFFF << uint(32-networkSize),
	}

	return s
}

func main() {
	logFileName := "/var/log/sendwolpacket.log"
	if runtime.GOOS == "windows" {
		logFileName = "sendwolpacket.log"
	}
	var logFile io.Writer
	logFile, err = os.OpenFile(logFileName, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		log.Fatalln("open file error !")
	}
	debugLog = log.New(logFile, "[Debug]", log.LstdFlags)
	debugLog.SetFlags(LstdFlags)

	http.HandleFunc("/wake", handler)
	err = http.ListenAndServe(":8181", nil)

	if err != nil {
		log.Fatal(err)
	}
}

func handler(w http.ResponseWriter, r *http.Request) {
	vars := r.URL.Query()
	debugLog.Printf("Get request params: %s\n", vars)
	mac, ok := vars["mac"]
	if !ok || len(mac) == 0 {
		debugLog.Printf("======Can't get the mac address")
		fmt.Fprintf(w, "Can't get the mac address")
		return
	}

	ip, ok := vars["ip"]
	if !ok || len(ip) == 0 || len(strings.Split(ip[0], ".")) != 4 {
		ip = []string{"255.255.255.255"}
	} else {
		ips := strings.Split(ip[0], ".")
		for i := 0; i < 4; i++ {
			tmpIp, err := strconv.Atoi(ips[i])
			if err != nil || (i == 0 && (tmpIp <= 0 || tmpIp > 255)) {
				ip = []string{"255.255.255.255"}
				break
			} else {
				if !(0 <= tmpIp && tmpIp <= 255) {
					ip = []string{"255.255.255.255"}
					break
				}
			}
		}
	}

	var networkSize int
	mask, ok := vars["mask"]
	if !ok || len(mask) == 0 {
		networkSize = 22
	} else {
		networkSize, err = strconv.Atoi(mask[0])
		if err != nil {
			debugLog.Printf("======Can't get the integer mask")
			fmt.Fprintf(w, "Can't get the integer mask")
			return
		}
	}

	broadcastIp := SubnetCalculator(ip[0], networkSize).GetBroadcastAddress()
	debugLog.Printf("broadcast ip is: %s\n", broadcastIp)
	debugLog.Printf("......Waking machine MAC: %s\n", mac[0])
	err = wakeCmd([]string{mac[0], broadcastIp})

	if err != nil {
		debugLog.Printf("======command finished with error: %v\n", err)
		fmt.Fprintf(w, "command finished with error: %v\n", err)
	} else {
		debugLog.Printf("======finished wakeonlan cmd======\n")
		fmt.Fprintf(w, "0")
	}

}
