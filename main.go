package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"flag"
	"fmt"
	"math/rand"
	"net"
	"nw/utils"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"
	"github.com/sirupsen/logrus"
	manuf "github.com/timest/gomanuf"
)

var log = logrus.New()

// ipNet 存放 IP地址和子网掩码
var ipNet *net.IPNet

// 本机的mac地址，发以太网包需要用到
var localHaddr net.HardwareAddr
var iface string

// 存放最终的数据，key[string] 存放的是IP地址
var data map[string]Info

// 计时器，在一段时间没有新的数据写入data中，退出程序，反之重置计时器
var t *time.Ticker
var do chan string

const (
	// 3秒的计时器
	START = "start"
	END   = "end"
)

type Info struct {
	// IP地址
	Mac net.HardwareAddr
	// 主机名
	Hostname string
	// 厂商信息
	Manuf string
}

// 格式化输出结果
// xxx.xxx.xxx.xxx  xx:xx:xx:xx:xx:xx  hostname  manuf
// xxx.xxx.xxx.xxx  xx:xx:xx:xx:xx:xx  hostname  manuf
func PrintData() {
	var keys utils.IPSlice
	for k := range data {
		keys = append(keys, utils.ParseIPString(k))
	}
	sort.Sort(keys)
	for _, k := range keys {
		d := data[k.String()]
		mac := ""
		if d.Mac != nil {
			mac = d.Mac.String()
		}
		fmt.Printf("%-15s %-17s %-30s %-10s\n", k.String(), mac, d.Hostname, d.Manuf)
	}
}

// 将抓到的数据集加入到data中，同时重置计时器
func pushData(ip string, mac net.HardwareAddr, hostname, manuf string) {
	// 停止计时器
	do <- START
	var mu sync.RWMutex
	mu.RLock()
	defer func() {
		// 重置计时器
		do <- END
		mu.RUnlock()
	}()
	if _, ok := data[ip]; !ok {
		data[ip] = Info{Mac: mac, Hostname: hostname, Manuf: manuf}
		return
	}
	info := data[ip]
	if len(hostname) > 0 && len(info.Hostname) == 0 {
		info.Hostname = hostname
	}
	if len(manuf) > 0 && len(info.Manuf) == 0 {
		info.Manuf = manuf
	}
	if mac != nil {
		info.Mac = mac
	}
	data[ip] = info
}

func setupNetInfo(f string) {
	var ifs []net.Interface
	var err error
	if f == "" {
		ifs, err = net.Interfaces()
		log.Info(ifs)
	} else {
		// 已经选择iface
		var it *net.Interface
		it, err = net.InterfaceByName(f)
		if err == nil {
			ifs = append(ifs, *it)
		}
	}
	if err != nil {
		log.Fatal("无法获取本地网络信息:", err)
	}
	for _, it := range ifs {

		log.Info("Flags:", it.Flags)

		if it.Flags == 0 {
			continue
		}

		addr, _ := it.Addrs()
		for _, a := range addr {
			if ip, ok := a.(*net.IPNet); ok && !ip.IP.IsLoopback() {

				if ip.IP.To4() != nil {
					ipNet = ip
					localHaddr = it.HardwareAddr
					iface = it.Name
					log.Info("iface:", iface)
					goto END
				}
			}
		}
	}
END:
	if ipNet == nil || len(localHaddr) == 0 {
		log.Fatal("无法获取本地网络信息")
	}
}

func localHost() {
	host, _ := os.Hostname()
	data[ipNet.IP.String()] = Info{Mac: localHaddr, Hostname: strings.TrimSuffix(host, ".local"), Manuf: manuf.Search(localHaddr.String())}
}

func listenARP(ctx context.Context) {
	log.Info("开始监听ARP", iface)
	handle, err := pcap.OpenLive(iface, 1024, false, 10*time.Second)
	if err != nil {
		log.Fatal("pcap打开失败1:", err)
	}
	defer handle.Close()
	handle.SetBPFFilter("arp")
	ps := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case <-ctx.Done():
			return
		case p := <-ps.Packets():
			arp := p.Layer(layers.LayerTypeARP).(*layers.ARP)
			if arp.Operation == 2 {
				mac := net.HardwareAddr(arp.SourceHwAddress)
				m := manuf.Search(mac.String())
				pushData(utils.ParseIP(arp.SourceProtAddress).String(), mac, "", m)
				if strings.Contains(m, "Apple") {
					go SendMdns(utils.ParseIP(arp.SourceProtAddress), mac)
				} else {
					go SendNbns(utils.ParseIP(arp.SourceProtAddress), mac)
				}
			}
		}
	}
}

// 发送arp包
// ip 目标IP地址
func sendArpPackage(ip utils.IP) {
	srcIp := net.ParseIP(ipNet.IP.String()).To4()
	dstIp := net.ParseIP(ip.String()).To4()
	if srcIp == nil || dstIp == nil {
		log.Fatal("ip 解析出问题")
	}
	// 以太网首部
	// EthernetType 0x0806  ARP
	ether := &layers.Ethernet{
		SrcMAC:       localHaddr,
		DstMAC:       net.HardwareAddr{0xff, 0xff, 0xff, 0xff, 0xff, 0xff},
		EthernetType: layers.EthernetTypeARP,
	}

	a := &layers.ARP{
		AddrType:          layers.LinkTypeEthernet,
		Protocol:          layers.EthernetTypeIPv4,
		HwAddressSize:     uint8(6),
		ProtAddressSize:   uint8(4),
		Operation:         uint16(1), // 0x0001 arp request 0x0002 arp response
		SourceHwAddress:   localHaddr,
		SourceProtAddress: srcIp,
		DstHwAddress:      net.HardwareAddr{0x00, 0x00, 0x00, 0x00, 0x00, 0x00},
		DstProtAddress:    dstIp,
	}

	buffer := gopacket.NewSerializeBuffer()
	var opt gopacket.SerializeOptions
	gopacket.SerializeLayers(buffer, opt, ether, a)
	outgoingPacket := buffer.Bytes()

	handle, err := pcap.OpenLive(iface, 2048, false, 30*time.Second)
	if err != nil {
		log.Fatal("pcap打开失败2:", err)
	}
	defer handle.Close()

	err = handle.WritePacketData(outgoingPacket)
	if err != nil {
		log.Fatal("发送arp数据包失败..")
	}
}

func sendARP() {
	// ips 是内网IP地址集合
	ips := utils.Table(ipNet)
	for _, ip := range ips {
		go sendArpPackage(ip)
	}
}

func listenMDNS(ctx context.Context) {
	handle, err := pcap.OpenLive(iface, 1024, false, 10*time.Second)
	if err != nil {
		log.Fatal("pcap打开失败3:", err.Error())
	}
	defer handle.Close()
	handle.SetBPFFilter("udp and port 5353")
	ps := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case <-ctx.Done():
			return
		case p := <-ps.Packets():
			if len(p.Layers()) == 4 {
				c := p.Layers()[3].LayerContents()
				if c[2] == 0x84 && c[3] == 0x00 && c[6] == 0x00 && c[7] == 0x01 {
					// 从网络层(ipv4)拿IP, 不考虑IPv6
					i := p.Layer(layers.LayerTypeIPv4)
					if i == nil {
						continue
					}
					ipv4 := i.(*layers.IPv4)
					ip := ipv4.SrcIP.String()
					// 把 hostname 存入到数据库
					h := ParseMdns(c)
					if len(h) > 0 {
						pushData(ip, nil, h, "")
					}
				}
			}
		}
	}
}

// 根据ip生成含mdns请求包，包存储在 buffer里
func mdns(buffer *utils.Buffer, ip string) {
	b := buffer.PrependBytes(12)
	binary.BigEndian.PutUint16(b, uint16(0))          // 0x0000 标识
	binary.BigEndian.PutUint16(b[2:], uint16(0x0100)) // 标识
	binary.BigEndian.PutUint16(b[4:], uint16(1))      // 问题数
	binary.BigEndian.PutUint16(b[6:], uint16(0))      // 资源数
	binary.BigEndian.PutUint16(b[8:], uint16(0))      // 授权资源记录数
	binary.BigEndian.PutUint16(b[10:], uint16(0))     // 额外资源记录数
	// 查询问题
	ipList := strings.Split(ip, ".")
	for j := len(ipList) - 1; j >= 0; j-- {
		ip := ipList[j]
		b = buffer.PrependBytes(len(ip) + 1)
		b[0] = uint8(len(ip))
		for i := 0; i < len(ip); i++ {
			b[i+1] = uint8(ip[i])
		}
	}
	b = buffer.PrependBytes(8)
	b[0] = 7 // 后续总字节
	copy(b[1:], []byte{'i', 'n', '-', 'a', 'd', 'd', 'r'})
	b = buffer.PrependBytes(5)
	b[0] = 4 // 后续总字节
	copy(b[1:], []byte{'a', 'r', 'p', 'a'})
	b = buffer.PrependBytes(1)
	// terminator
	b[0] = 0
	// type 和 classIn
	b = buffer.PrependBytes(4)
	binary.BigEndian.PutUint16(b, uint16(12))
	binary.BigEndian.PutUint16(b[2:], 1)
}

func SendMdns(ip utils.IP, mhaddr net.HardwareAddr) {
	srcIp := net.ParseIP(ipNet.IP.String()).To4()
	dstIp := net.ParseIP(ip.String()).To4()
	ether := &layers.Ethernet{
		SrcMAC:       localHaddr,
		DstMAC:       mhaddr,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip4 := &layers.IPv4{
		Version:  uint8(4),
		IHL:      uint8(5),
		TTL:      uint8(255),
		Protocol: layers.IPProtocolUDP,
		SrcIP:    srcIp,
		DstIP:    dstIp,
	}
	bf := utils.NewBuffer()
	mdns(bf, ip.String())
	udpPayload := bf.Data
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(60666),
		DstPort: layers.UDPPort(5353),
	}
	udp.SetNetworkLayerForChecksum(ip4)
	udp.Payload = udpPayload // todo
	buffer := gopacket.NewSerializeBuffer()
	opt := gopacket.SerializeOptions{
		FixLengths:       true, // 自动计算长度
		ComputeChecksums: true, // 自动计算checksum
	}
	err := gopacket.SerializeLayers(buffer, opt, ether, ip4, udp, gopacket.Payload(udpPayload))
	if err != nil {
		log.Fatal("Serialize layers出现问题:", err)
	}
	outgoingPacket := buffer.Bytes()

	handle, err := pcap.OpenLive(iface, 1024, false, 10*time.Second)
	if err != nil {
		log.Fatal("pcap打开失败4:", err)
	}
	defer handle.Close()
	err = handle.WritePacketData(outgoingPacket)
	if err != nil {
		log.Fatal("发送udp数据包失败..")
	}
}

// 参数data  开头是 dns的协议头 0x0000 0x8400 0x0000 0x0001(ans) 0x0000 0x0000
// 从 mdns响应报文中获取主机名
func ParseMdns(data []byte) string {
	var buf bytes.Buffer
	i := bytes.Index(data, []byte{0x05, 0x6c, 0x6f, 0x63, 0x61, 0x6c, 0x00})
	if i < 0 {
		return ""
	}

	for s := i - 1; s > 1; s-- {
		num := i - s
		if s-2 < 0 {
			break
		}
		// 包括 .local_ 7 个字符
		if bto16([]byte{data[s-2], data[s-1]}) == uint16(num+7) {
			return utils.Reverse(buf.String())
		}
		buf.WriteByte(data[s])
	}

	return ""
}

func bto16(b []byte) uint16 {
	if len(b) != 2 {
		log.Fatal("b只能是2个字节")
	}
	return uint16(b[0])<<8 + uint16(b[1])
}

func listenNBNS(ctx context.Context) {
	handle, err := pcap.OpenLive(iface, 1024, false, 10*time.Second)
	if err != nil {
		log.Fatal("pcap打开失败5:", err)
	}
	defer handle.Close()
	handle.SetBPFFilter("udp and port 137 and dst host " + ipNet.IP.String())
	ps := gopacket.NewPacketSource(handle, handle.LinkType())
	for {
		select {
		case <-ctx.Done():
			return
		case p := <-ps.Packets():
			if len(p.Layers()) == 4 {
				c := p.Layers()[3].LayerContents()
				if len(c) > 8 && c[2] == 0x84 && c[3] == 0x00 && c[6] == 0x00 && c[7] == 0x01 {
					// 从网络层(ipv4)拿IP, 不考虑IPv6
					i := p.Layer(layers.LayerTypeIPv4)
					if i == nil {
						continue
					}
					ipv4 := i.(*layers.IPv4)
					ip := ipv4.SrcIP.String()
					// 把 hostname 存入到数据库
					m := ParseNBNS(c)
					if len(m) > 0 {
						pushData(ip, nil, m, "")
					}
				}
			}
		}
	}
}

// 根据ip生成含mdns请求包，包存储在 buffer里
func nbns(buffer *utils.Buffer) {
	rand.Seed(time.Now().UnixNano())
	tid := rand.Intn(0x7fff)
	b := buffer.PrependBytes(12)
	binary.BigEndian.PutUint16(b, uint16(tid))        // 0x0000 标识
	binary.BigEndian.PutUint16(b[2:], uint16(0x0010)) // 标识
	binary.BigEndian.PutUint16(b[4:], uint16(1))      // 问题数
	binary.BigEndian.PutUint16(b[6:], uint16(0))      // 资源数
	binary.BigEndian.PutUint16(b[8:], uint16(0))      // 授权资源记录数
	binary.BigEndian.PutUint16(b[10:], uint16(0))     // 额外资源记录数
	// 查询问题
	b = buffer.PrependBytes(1)
	b[0] = 0x20
	b = buffer.PrependBytes(32)
	copy(b, []byte{0x43, 0x4b})
	for i := 2; i < 32; i++ {
		b[i] = 0x41
	}

	b = buffer.PrependBytes(1)
	// terminator
	b[0] = 0
	// type 和 classIn
	b = buffer.PrependBytes(4)
	binary.BigEndian.PutUint16(b, uint16(33))
	binary.BigEndian.PutUint16(b[2:], 1)
}

func SendNbns(ip utils.IP, mhaddr net.HardwareAddr) {
	srcIp := net.ParseIP(ipNet.IP.String()).To4()
	dstIp := net.ParseIP(ip.String()).To4()
	ether := &layers.Ethernet{
		SrcMAC:       localHaddr,
		DstMAC:       mhaddr,
		EthernetType: layers.EthernetTypeIPv4,
	}

	ip4 := &layers.IPv4{
		Version:  uint8(4),
		IHL:      uint8(5),
		TTL:      uint8(255),
		Protocol: layers.IPProtocolUDP,
		SrcIP:    srcIp,
		DstIP:    dstIp,
	}
	bf := utils.NewBuffer()
	nbns(bf)
	udpPayload := bf.Data
	udp := &layers.UDP{
		SrcPort: layers.UDPPort(61666),
		DstPort: layers.UDPPort(137),
	}
	udp.SetNetworkLayerForChecksum(ip4)
	udp.Payload = udpPayload
	buffer := gopacket.NewSerializeBuffer()
	opt := gopacket.SerializeOptions{
		FixLengths:       true, // 自动计算长度
		ComputeChecksums: true, // 自动计算checksum
	}
	err := gopacket.SerializeLayers(buffer, opt, ether, ip4, udp, gopacket.Payload(udpPayload))
	if err != nil {
		log.Fatal("Serialize layers出现问题:", err)
	}
	outgoingPacket := buffer.Bytes()

	handle, err := pcap.OpenLive(iface, 1024, false, 10*time.Second)
	if err != nil {
		log.Fatal("pcap打开失败6:", err)
	}
	defer handle.Close()
	err = handle.WritePacketData(outgoingPacket)
	if err != nil {
		log.Fatal("发送udp数据包失败..")
	}
}

func ParseNBNS(data []byte) string {
	var buf bytes.Buffer
	i := bytes.Index(data, []byte{0x20, 0x43, 0x4b, 0x41, 0x41})
	if i < 0 || len(data) < 32 {
		return ""
	}
	index := i + 1 + 0x20 + 12
	// data[index-1]是在 number of names 的索引上，如果number of names 为0，退出
	if data[index-1] == 0x00 {
		return ""
	}
	for t := index; ; t++ {
		// 0x20 和 0x00 是终止符
		if data[t] == 0x20 || data[t] == 0x00 {
			break
		}
		buf.WriteByte(data[t])
	}
	return buf.String()
}

func main() {
	// allow non root user to execute by compare with euid
	log.Info("goscan start...")
	log.Info("goscan version: ", os.Geteuid())
	// if os.Geteuid() != 0 {
	// 	log.Fatal("goscan must run as root.")
	// }
	flag.StringVar(&iface, "I", "", "Network interface name")
	flag.Parse()
	// 初始化 data
	data = make(map[string]Info)
	do = make(chan string)
	// 初始化 网络信息

	log.Info("iface", iface)
	setupNetInfo(iface)

	ctx, cancel := context.WithCancel(context.Background())
	go listenARP(ctx)
	go listenMDNS(ctx)
	go listenNBNS(ctx)
	go sendARP()
	go localHost()

	t = time.NewTicker(4 * time.Second)
	for {
		select {
		case <-t.C:
			PrintData()
			cancel()
			goto END
		case d := <-do:
			switch d {
			case START:
				t.Stop()
			case END:
				// 接收到新数据，重置2秒的计数器
				t = time.NewTicker(2 * time.Second)
			}
		}
	}
	time.Sleep(5 * time.Second)
	log.Info("结束...")
END:
	time.Sleep(5 * time.Second)
	log.Info("goscan end...")

}
