#include "IcmpDetect.h"
#include <assert.h>

#define THREAD_TIMEOUT	5000
#define NR_ROUTER		1 // 网关路由器主机号
#define TICKS			50

static List g_aliveHosts = NULL; // 存活主机列表
static int g_ticks = TICKS;

DWORD WINAPI recvICMPThread(LPVOID param)
{
	PPCAP_PARAM _param = (PPCAP_PARAM)param;
	struct bpf_program fcode;
	uint32_t netmask;

	if (_param->d->addresses != NULL)
	{
		// 获得接口第一个地址的掩码
		netmask = ((struct sockaddr_in *)(_param->d->addresses->netmask))->sin_addr.S_un.S_addr;
	}
	else
	{
		// 如果接口没有地址，假设一个C类的掩码
		netmask = 0xffffff;
	}

	// 编译过滤器
	if (pcap_compile(_param->adhandle, &fcode, "icmp", 1, netmask) < 0)
	{
		printf("\nUnable to compile the packet filter. Check the syntax.\n");
		pcap_freealldevs(_param->alldevs);
		return EXIT_FAILURE;
	}

	// 设置
	if (pcap_setfilter(_param->adhandle, &fcode) < 0)
	{
		printf("\nError setting the filter.\n");
		pcap_freealldevs(_param->alldevs);
		return EXIT_FAILURE;
	}

	// 释放设备列表并开始捕获
	printf("\nThread[%d] listening on %s...\n", GetCurrentThreadId(), _param->d->description);
	pcap_freealldevs(_param->alldevs);
	pcap_loop(_param->adhandle, 0, icmp_packet_handler, NULL);

	return EXIT_SUCCESS;;
}

void icmp_packet_handler(uint8_t *param, const struct pcap_pkthdr *header, const uint8_t *pkt_data)
{
	ether_header *eh;
	ip_header *iph;
	icmp_header *icmph;
	uint32_t ip_len;
	ListElement e;

	eh = (ether_header*)pkt_data;
	iph = (ip_header*)(pkt_data + sizeof(ether_header));
	ip_len = (iph->ver_ihl & 0x0F) << 2;
	icmph = (icmp_header*)(pkt_data + sizeof(ether_header) + ip_len);

	// 判断是否是回复我发的 ICMP 报文
	if (icmph->type == ICMP_REPLY &&
		icmph->id == (uint16_t)GetCurrentProcessId())
	{
		e.ipv4 = iph->saddr;
		memcpy(e.mac, eh->saddr, MAC_LEN);
		List_Add(g_aliveHosts, e); // 将存活主机的 IPv4 和 MAC 加入列表

		// 每探测到 TICKS 台主机就打印一个'.'
		if (g_ticks-- == 0)
		{
			printf(".");
			g_ticks = TICKS;
		}
	}
}

/////////////////////////////////////////////// public ///////////////////////////////////////////////

IcmpDetect::IcmpDetect(NetworkAdapter &adapter)
{
	m_adhandle = adapter.getAdapterHandle();
	g_aliveHosts = List_Create();
}

IcmpDetect::~IcmpDetect()
{

}

void IcmpDetect::beginDetect(NetworkAdapter &adapter)
{
	uint8_t packet[sizeof(icmp_packet)];
	uint32_t netaddr; // 网络地址
	uint32_t netmask; // 网络掩码
	uint32_t nr_hosts; // 网络内可被分配 ip 的主机数
	uint32_t local_ip;
	uint32_t dst_ip;
	uint8_t local_mac[MAC_LEN];
	uint8_t router_mac[MAC_LEN];

	PCAP_PARAM param;
	param.adhandle = adapter.getAdapterHandle();
	param.alldevs = adapter.getDeviceList();
	param.d = adapter.getCurrentDevice();

	assert(param.adhandle && param.alldevs && param.d);

	adapter.getLocalIpAndMask(&local_ip, &netmask);
	adapter.GetLocalMac(local_mac);
	adapter.GetNetAddrOfRouter(NULL, router_mac);
	netaddr = local_ip & netmask;
	nr_hosts = htonl(~netmask) - 1;

	// 创建接收线程
	m_hRecvThread = CreateThread(NULL, 0, recvICMPThread,
		(LPVOID)&param, 0, NULL);
	if (m_hRecvThread == NULL)
	{
		printf("\nCreateThread Error: #%d", GetLastError());
		return;
	}

	// 发送 ICMP 请求报文
	for (uint32_t host = 1; host < nr_hosts; host++)
	{
		dst_ip = netaddr | htonl(host);
		make_icmp_packet(packet,
			local_mac, local_ip,
			router_mac, dst_ip,
			ICMP_REQUEST, host);
		send_icmp_packet(packet, sizeof(packet));
	}
}

List IcmpDetect::getAliveHosts()
{
	WaitForSingleObject(m_hRecvThread, THREAD_TIMEOUT);
	return g_aliveHosts;
}

/////////////////////////////////////////////// private ///////////////////////////////////////////////

uint16_t IcmpDetect::cksum(uint16_t *p, int len)
{
	int cksum = 0;
	uint16_t answer = 0;

	// 以16bits为单位累加
	while (len > 1)
	{
		uint16_t t = *p;
		cksum += *p++;
		len -= 2;
	}
	// 如果数据的字节数为奇数, 将最后一个字节视为16bits的高8bits, 低8bits补0, 继续累加
	if (len == 1)
	{
		answer = *(uint16_t *)p;
		cksum += answer;
	}
	// cksum是32bits的int, 而校验和为16bits, 需将cksum的高16bits加到低16bits上
	cksum = (cksum >> 16) + (cksum & 0xffff);
	// 按位求反
	return (~(uint16_t)cksum);
}

void IcmpDetect::make_icmp_packet(uint8_t* packet,
	uint8_t* src_mac, uint32_t src_ip,
	uint8_t* dst_mac, uint32_t dst_ip,
	uint8_t type, uint16_t seq)
{
	icmp_packet icmp_pkt;
	memset(&icmp_pkt, 0, sizeof(icmp_packet));

	// -----------------填充以太网首部-----------------
	memcpy(icmp_pkt.eh.daddr, dst_mac, MAC_LEN);
	memcpy(icmp_pkt.eh.saddr, src_mac, MAC_LEN);
	icmp_pkt.eh.prototype = htons(ETHPROTOCAL_IPV4);

	// -----------------填充 IPv4 首部-----------------
	icmp_pkt.iph.ver_ihl = 0x45;
	icmp_pkt.iph.tlen = htons(sizeof(icmp_pkt) - sizeof(ether_header));
	icmp_pkt.iph.ttl = 128;
	icmp_pkt.iph.proto = IPV4PROTOCOL_ICMP;
	icmp_pkt.iph.saddr = src_ip;
	icmp_pkt.iph.daddr = dst_ip;
	icmp_pkt.iph.cksum = cksum((uint16_t*)&icmp_pkt.iph, sizeof(ip_header));

	// -----------------填充 ICMP 首部-----------------
	icmp_pkt.icmph.type = type;
	icmp_pkt.icmph.id = (uint16_t)GetCurrentProcessId();
	icmp_pkt.icmph.seq = htons(seq);
	memset(icmp_pkt.data, 0xCC, sizeof(icmp_pkt.data));
	icmp_pkt.icmph.cksum = cksum((uint16_t*)&icmp_pkt.icmph,
		sizeof(icmp_header) + sizeof(icmp_pkt.data));

	memcpy(packet, &icmp_pkt, sizeof(icmp_pkt));
}

void IcmpDetect::send_icmp_packet(uint8_t* packet, int len)
{
	if (pcap_sendpacket(m_adhandle, packet, len) == -1)
		printf("packet sending error");
}

