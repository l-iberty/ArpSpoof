#ifndef HEADERS_H
#define HEADERS_H

#define MAC_LEN				6		// MAC ��ַ, 48 bits = 6 bytes
#define IPV4_LEN			4		// IPV4 ��ַ, 32 bits = 4 bytes
#define PADDING_LEN			18		// ARP ���ݰ�����Ч�غɳ���
#define ICMP_DATA_LEN		32		// ICMP ���ݰ�����Ч�غɳ���

typedef unsigned char u_char;
typedef unsigned short u_short;
typedef unsigned int u_int;


#pragma pack(push, 1)

// ��̫���ײ�

#define ETHPROTOCAL_IPV4		0x0800 // ��̫���ϲ�Э������: IPv4
#define ETHPROTOCAL_ARP			0x0806 // ��̫���ϲ�Э������: ARP

typedef struct ether_header {
	u_char daddr[MAC_LEN];				// Ŀ��MAC��ַ
	u_char saddr[MAC_LEN];				// ԴMAC��ַ
	u_short prototype;					// �ϲ�Э������ (0x0800->IPv4, 0x0806->ARP)
} ether_header;

// ��̫�� ARP �ֶ�

#define HARD_ETHERNET			0x0001
#define ARP_REQUEST				0x0001 // ARP ����
#define ARP_RESPONCE			0x0002 // ARP Ӧ��

typedef struct arp_header {
	// ARP �ײ�
	u_short arp_hrd;				// Ӳ������
	u_short arp_pro;				// Э������
	u_char arp_hln;					// Ӳ����ַ����
	u_char arp_pln;					// Э���ַ����
	u_short arp_op;					// ѡ��
	u_char arp_shaddr[MAC_LEN];		// ������ MAC ��ַ
	u_int arp_spaddr;				// ������Э��(IP)��ַ
	u_char arp_thaddr[MAC_LEN];		// Ŀ�� MAC ��ַ
	u_int arp_tpaddr;				// Ŀ��Э��(IP)��ַ
} arp_header;

// ARP ��
typedef struct arp_packet {
	ether_header eh;				// ��̫���ײ�
	arp_header ah;					// ARP �ײ�
	u_char padding[PADDING_LEN];
} arp_packet;

// IPv4 Header

#define IPV4PROTOCOL_ICMP	1

typedef struct ip_header {
	u_char  ver_ihl;				// �汾 (4 bits) + �ײ����� (4 bits)
	u_char  tos;					// ��������(Type of service) 
	u_short tlen;					// �ܳ�(Total length) 
	u_short identification;			// ��ʶ(Identification)
	u_short flags_fo;				// ��־λ(Flags) (3 bits) + ��ƫ����(Fragment offset) (13 bits)
	u_char  ttl;					// ���ʱ��(Time to live)
	u_char  proto;					// �ϲ�Э��(Protocol)
	u_short cksum;					// �ײ�У���(Header checksum)
	u_int  saddr;				    // Դ��ַ(Source address)
	u_int  daddr;					// Ŀ�ĵ�ַ(Destination address)
}ip_header;

// ICMP Header

#define ICMP_REQUEST	8
#define ICMP_REPLY		0

typedef struct icmp_header {
	u_char type;				// ICMP���ݱ�����
	u_char code;				// ����
	u_short cksum;				// У���
	u_short id;					// ��ʶ(ͨ��Ϊ��ǰ����pid)
	u_short seq;				// ���
}icmp_header;

// ICMP ��
typedef struct icmp_packet {
	ether_header eh;				// ��̫���ײ�
	ip_header iph;					// IPv4 �ײ�
	icmp_header icmph;				// ICMP �ײ�
	u_char data[ICMP_DATA_LEN];
} icmp_packet;

// TCP Header
typedef struct tcp_header {
	u_short sport;				// Դ�˿ں�
	u_short dport;				// Ŀ�Ķ˿ں�
	u_int seq;					// ���
	u_int ack;					// ȷ�Ϻ�
	u_char lenres;				// 4 bits ������ƫ�ƺ� 4 bits �ı����ֶ�
	u_char flag;				// ��־
	u_short win;				// ���ڳ���
	u_short cksum;				// У���
	u_short urp;				// ����ָ��
}tcp_header;

// UDP �ײ�
typedef struct udp_header {
	u_short sport;           	// Դ�˿�(Source port)
	u_short dport;          	// Ŀ�Ķ˿�(Destination port)
	u_short len;				// UDP���ݰ�����(Datagram length)
	u_short cksum;         		// У���(Checksum)
}udp_header;

#pragma pack(pop)

#endif // HEADERS_H