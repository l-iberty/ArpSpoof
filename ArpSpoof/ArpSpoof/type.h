#ifndef TYPE_H
#define TYPE_H

typedef unsigned char	uint8_t;
typedef unsigned short	uint16_t;
typedef unsigned int	uint32_t;

#define MAC_LEN 6

typedef struct addr_entry
{
	uint32_t ipv4;
	uint8_t mac[MAC_LEN];
} addr_entry;

#endif // TYPE_H
