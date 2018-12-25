#ifndef ICMP_DETECT_H
#define ICMP_DETECT_H

#include "Pcap.h"
#include "headers.h"
#include "NetworkAdapter.h"
#include "List.h"

DWORD WINAPI recvICMPThread(LPVOID param);

// pcap_loop 回调函数
void icmp_packet_handler(uint8_t *param, const struct pcap_pkthdr *header, const uint8_t *pkt_data);

// 用于封装传递给线程函数的参数
typedef struct {
	pcap_t* adhandle;
	pcap_if_t* alldevs;
	pcap_if_t* d;
} PCAP_PARAM, *PPCAP_PARAM;


class IcmpDetect {
public:
	IcmpDetect(NetworkAdapter &adapter);
	~IcmpDetect();
	List getAliveHosts();
	void beginDetect(NetworkAdapter &adapter);

private:
	uint16_t cksum(uint16_t *p, int len);

	void make_icmp_packet(uint8_t *packet,
		uint8_t *src_mac, uint32_t src_ip,
		uint8_t *dst_mac, uint32_t dst_ip,
		uint8_t type, uint16_t seq);

	void send_icmp_packet(uint8_t* packet, int len);

private:
	pcap_t *m_adhandle; // 网络适配器句柄
	HANDLE m_hRecvThread; // 接收ICMP报文的线程句柄
};

#endif // ICMP_DETECT_H
