#include "protocols.h"
#include "queue.h"
#include "lib.h"
#include <arpa/inet.h>  // For ntohs, ntohl, htons, htonl
#include <string.h>


/* Routing table */
struct route_table_entry *rtable;
int rtable_len;

/* Mac table */
struct arp_table_entry *mac_table;
int mac_table_len;

// Debugg 

// Network Order
void printIp(uint32_t ipaddr, char* msg) {
    printf("%s: %u.%u.%u.%u\n", msg 
                        , ipaddr & 0xFF
                        , (ipaddr >> 8) & 0xFF
                        , (ipaddr >> 16) & 0xFF
                        , (ipaddr >> 24) & 0xFF);
}

void print_cmp_mac(char *m1, char *m2, char* msg) {
    printf("%s: %x.%x.%x.%x.%x.%x || %x.%x.%x.%x.%x.%x\n", msg 
                        , m1[0], m1[1], m1[2], m1[3], m1[4], m1[5]
						, m2[0], m2[1], m2[2], m2[3], m2[4], m2[5]);
}

//


struct route_table_entry *get_best_route(uint32_t ip) {
	// Debugg snippets
	// printIp(ip, "Looking for");
	// printIp(rtable->prefix, "Prefix");
	// printIp(rtable->mask & ip, "Maked addr");
	struct route_table_entry *best = rtable;
	int found = 0, i = 0;
	for (i = 0; i < rtable_len && !found; i++) {
		if((rtable[i].mask & ip) == rtable[i].prefix) {
			printf("gasit\n");
			best = &rtable[i];
			found = 1;
		}
	}
	for (; i < rtable_len; i++) {
		if ((rtable[i].mask > best->mask) && rtable[i].prefix == (rtable[i].mask & ip))
			best = &rtable[i];
	}

	// printIp(ip, "Looking for");
	// printIp(ip & best->mask, "IP MASKED");
	// printIp(best->mask, "Mask");
	// printIp(best->prefix, "Prefix");
	// printIp(best->next_hop, "Next hop");

	return best;
}

struct arp_table_entry* get_mac_entry(uint32_t given_ip) {
	printf("%d\n", mac_table_len);
	printIp(given_ip, "Looking for");
	for (int i = 0; i < mac_table_len; i++) {
		if (mac_table[i].ip == given_ip) {
			printIp(mac_table[i].ip, "Analyzing ip");
			return &mac_table[i];
		}
	}
	printf("MAC NOT RECOGNIZED\n");
	return NULL;
}

int main(int argc, char *argv[])
{
	char buf[MAX_PACKET_LEN];

	// Do not modify this line
	init(argv + 2, argc - 2);

	// Read routing table
	rtable = malloc(sizeof(struct route_table_entry) * 70000);
	DIE(rtable == NULL, "Failed malloc\n");
	rtable_len = read_rtable(argv[1], rtable);

	// Read static MAC
	mac_table = malloc(sizeof(struct arp_table_entry) * 100);
	DIE(mac_table == NULL, "Failed malloc\n");
	mac_table_len = parse_arp_table("arp_table.txt", mac_table);

	while (1) {

		size_t interface;
		size_t len;

		interface = recv_from_any_link(buf, &len);
		DIE(interface < 0, "recv_from_any_links");

    // TODO: Implement the router forwarding logic
		struct ether_hdr *eth_hdr = (struct ether_hdr *) buf;
		
		if (eth_hdr->ethr_type == ntohs(ETHERTYPE_IP)) {
			// We have an ip_package
			printf("We've received an IP package\n");

			struct ip_hdr *ip_hdr = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
			
			uint16_t check = ntohs(ip_hdr->checksum);
			ip_hdr->checksum = 0;
			
			if (check != checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr))) {
				printf("IP checksum failed. Dropping packet...\n");
				continue;
			}

			struct route_table_entry *best_route = get_best_route(ip_hdr->dest_addr);
		
			if (!best_route) {
				printf("Destination host unreachable!\n");
				continue;
			}

			// Check ttl
			if (ip_hdr->ttl <= 1) {
				printf("TTL reached 0\n");
				continue;
			}
			ip_hdr->ttl--;

			ip_hdr->checksum = 0;
			ip_hdr->checksum = htons(checksum((u_int16_t *)ip_hdr, sizeof(struct ip_hdr)));

			struct arp_table_entry *mac_entry = get_mac_entry(best_route->next_hop);
			if (mac_entry == NULL) {
				// we need to wait for arp request
				// TBI
				continue;
			}
			memcpy(eth_hdr->ethr_dhost, mac_entry->mac, 6);
			get_interface_mac(best_route->interface, eth_hdr->ethr_shost);
			send_to_link(len, buf, best_route->interface);
		}

		// TO-DO: check for ARP request

    /* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */


	}
}

