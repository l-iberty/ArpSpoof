#ifndef ARP_SPROOF_H
#define ARP_SPROOF_H

#include "NetworkAdapter.h"

class ArpSpoof {
public:
	ArpSpoof();
	~ArpSpoof();
	u_int getNetAddr();
	u_int getHostsnum();
	void beignAttack(u_int dst_ip);

private:
	void make_arp_packet(u_char* packet, u_char* src_mac, u_int src_ip, u_int dst_ip);

private:
	NetworkAdapter m_Adapter;
	u_int m_netaddr; // 网络地址
	u_int m_netmask; // 网络掩码
	u_int m_hostsnum; // 网络内内可容纳的主机数 (除去主机地址全0的网络地址和全1的广播地址)
	u_char m_local_mac[MAC_LEN]; // 本机 MAC 地址
	u_int m_local_ip; // 本机 IP 地址
	u_char m_router_mac[MAC_LEN]; // 路由器 MAC 地址
	u_int m_router_ip; // 路由器 IP 地址
};

#endif // ARP_SPROOF_H
