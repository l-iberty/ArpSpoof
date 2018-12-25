#ifndef HEADERS_H
#define HEADERS_H
#include "type.h"

#define MAC_LEN				6		// MAC 地址, 48 bits = 6 bytes
#define IPV4_LEN			4		// IPV4 地址, 32 bits = 4 bytes
#define PADDING_LEN			18		// ARP 数据包的有效载荷长度
#define ICMP_DATA_LEN		32		// ICMP 数据包的有效载荷长度


#pragma pack(push, 1)

#define ETHPROTOCAL_IPV4		0x0800 // 以太网上层协议类型: IPv4
#define ETHPROTOCAL_ARP			0x0806 // 以太网上层协议类型: ARP

typedef struct ether_header 
{
	uint8_t daddr[MAC_LEN];				// 目的 MAC 地址
	uint8_t saddr[MAC_LEN];				// 源 MAC 地址
	uint16_t prototype;					// 上层协议类型 (0x0800->IPv4, 0x0806->ARP)
} ether_header;

#define HARD_ETHERNET			0x0001
#define ARP_REQUEST				0x0001 // ARP 请求
#define ARP_RESPONCE			0x0002 // ARP 应答

typedef struct arp_header 
{
	uint16_t arp_hrd;				// 硬件类型
	uint16_t arp_pro;				// 上层协议类型
	uint8_t arp_hln;				// 硬件地址长度
	uint8_t arp_pln;				// 协议地址长度
	uint16_t arp_op;				// 操作选项 (请求 or 应答)
	uint8_t arp_shaddr[MAC_LEN];	// 发送者硬件地址 (MAC)
	uint32_t arp_spaddr;			// 发送者协议地址 (IPv4)
	uint8_t arp_thaddr[MAC_LEN];	// 目标硬件地址 (MAC)
	uint32_t arp_tpaddr;			// 目标协议地址 (IPv4)
} arp_header;

typedef struct arp_packet 
{
	ether_header eh;				// 以太网首部
	arp_header ah;					// ARP 首部
} arp_packet;

#define IPV4PROTOCOL_ICMP	1

typedef struct ip_header 
{
	uint8_t  ver_ihl;				// 版本 (4 bits) + 首部长度 (4 bits)
	uint8_t  tos;					// 服务类型(Type of service) 
	uint16_t tlen;					// 总长(Total length) 
	uint16_t identification;		// 标识(Identification)
	uint16_t flags_fo;				// 标志位(Flags) (3 bits) + 段偏移量(Fragment offset) (13 bits)
	uint8_t  ttl;					// 存活时间(Time to live)
	uint8_t  proto;					// 上层协议(Protocol)
	uint16_t cksum;					// 首部校验和(Header checksum)
	uint32_t  saddr;				// 源地址(Source address)
	uint32_t  daddr;				// 目的地址(Destination address)
} ip_header;

#define ICMP_REQUEST	8
#define ICMP_REPLY		0

typedef struct icmp_header 
{
	uint8_t type;				// ICMP数据报类型
	uint8_t code;				// 编码
	uint16_t cksum;				// 校验和
	uint16_t id;				// 标识(通常为当前进程pid)
	uint16_t seq;				// 序号
} icmp_header;

typedef struct icmp_packet {
	ether_header eh;				// 以太网首部
	ip_header iph;					// IPv4 首部
	icmp_header icmph;				// ICMP 首部
	uint8_t data[ICMP_DATA_LEN];
} icmp_packet;

typedef struct tcp_header 
{
	uint16_t sport;				// 源端口号
	uint16_t dport;				// 目的端口号
	uint32_t seq;				// 序号
	uint32_t ack;				// 确认号
	uint8_t lenres;				// 4 bits 的数据偏移和 4 bits 的保留字段
	uint8_t flag;				// 标志
	uint16_t win;				// 窗口长度
	uint16_t cksum;				// 校验和
	uint16_t urp;				// 紧急指针
} tcp_header;

typedef struct udp_header 
{
	uint16_t sport;           	// 源端口(Source port)
	uint16_t dport;          	// 目的端口(Destination port)
	uint16_t len;				// UDP数据包长度(Datagram length)
	uint16_t cksum;         	// 校验和(Checksum)
} udp_header;

#pragma pack(pop)

#endif // HEADERS_H
