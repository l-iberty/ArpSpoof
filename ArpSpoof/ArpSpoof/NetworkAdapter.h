#ifndef NETWORK_ADAPTER_H
#define NETWORK_ADAPTER_H

#include "Pcap.h"
#include "headers.h"
#include <Shlwapi.h>
#include <Packet32.h>
#include <Windows.h>
#include <ntddndis.h>
#include <Iphlpapi.h>

#define MAX_SNAP_LEN	65536

class NetworkAdapter {
public:
	NetworkAdapter();
	~NetworkAdapter();

	pcap_t* openAdapter();
	pcap_if_t* getDeviceList();
	pcap_if_t* getCurrentDevice();
	pcap_t* getAdapterHandle();
	int getLocalIpAndMask(u_int *pIp, u_int *pMask);

	BOOLEAN GetLocalMac(PUCHAR MacAddr);
	VOID GetNetAddrOfRouter(PDWORD pIpAddr, PUCHAR MacAddr);

private:
	int initDeviceList();
	void getAdapterParams();

private:
	pcap_if_t *m_alldevs;				// 网络适配器链表结构
	pcap_if_t *m_d;						// 适配器链表节点定位指针
	int m_devnum;						// 适配器数量 (unused)
	pcap_t *m_adhandle;					// pcap句柄
	pcap_addr_t *m_paddr;				// 网卡地址结构
	char m_AdapterName[PCAP_BUF_SIZE];
};

#endif // NETWORK_ADAPTER_H
