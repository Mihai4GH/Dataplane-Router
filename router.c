#include "protocols.h"
#include "queue.h"
#include "lib.h"
#include <arpa/inet.h>  // For ntohs, ntohl, htons, htonl
#include <string.h>


/* Routing table */
struct route_table_entry *rtable;
int rtable_len;

/* Mac table */

#define CAPACITY 100
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
    printf("%s: %02x:%02x:%02x:%02x:%02x:%02x || %02x:%02x:%02x:%02x:%02x:%02x\n", msg 
                        , m1[0] & 0xff, m1[1] & 0xff, m1[2] & 0xff, m1[3] & 0xff, m1[4] & 0xff, m1[5] & 0xff
						, m2[0] & 0xff, m2[1] & 0xff, m2[2] & 0xff, m2[3] & 0xff, m2[4] & 0xff, m2[5] & 0xff);
}

void print_mac_table_enty() {
	for(int i = 0; i < mac_table_len; i++){
		char *m1 = (char *)mac_table[i].mac;
		uint32_t ip = mac_table[i].ip;
		printf("%u.%u.%u.%u <=> %02x:%02x:%02x:%02x:%02x:%02x\n" 
                        , ip & 0xFF
                        , (ip >> 8) & 0xFF
                        , (ip >> 16) & 0xFF
                        , (ip >> 24) & 0xFF
						, m1[0] & 0xff, m1[1] & 0xff, m1[2] & 0xff, m1[3] & 0xff, m1[4] & 0xff, m1[5] & 0xff);
	}
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

unsigned int ip_to_int(char *ip_str)
{
    struct in_addr addr;
    inet_pton(AF_INET, ip_str, &addr);  // Convert IP string to binary format
    return ntohl(addr.s_addr);          // Convert to host byte order (32-bit integer)
}

// Function to send an arp request on a specific interface, looking for ip
void send_arp_request(size_t interface, uint32_t ip) {
	char buf[64] = {0}; 
	struct ether_hdr *eth = (struct ether_hdr *)buf;
	struct arp_hdr *arp = (struct arp_hdr *)(buf + sizeof(struct ether_hdr)); 

	// Initialize the ether header
	eth->ethr_type = ntohs(ETHERTYPE_ARP);
	get_interface_mac(interface, eth->ethr_shost);
	memset(eth->ethr_dhost, 0xff, 6);

	// Initialize the arp header
	arp->hw_type = htons(1); // Ether
	arp->proto_type = htons(ETHERTYPE_IP); // IPv4 
	arp->hw_len = 6;
	arp->proto_len = 4;	
	arp->opcode = htons(ARP_REQUEST); // REQUEST OPERATION
	// Sender hw/prot adress
	get_interface_mac(interface, arp->shwa);
	arp->sprotoa = ntohl(ip_to_int(get_interface_ip(interface)));
	// Just a print for debugg
	printIp(ntohl(ip_to_int(get_interface_ip(interface))), get_interface_ip(interface));

	// Target hw/prot addr
	arp->tprotoa = ip;
	memset(arp->thwa, 0, 6);

	printf("Sending arp Request\n");
	send_to_link(42, buf, interface);
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
	mac_table = malloc(sizeof(struct arp_table_entry) * CAPACITY);
	DIE(mac_table == NULL, "Failed malloc\n");
	mac_table_len = 0;
	// mac_table_len = parse_arp_table("arp_table.txt", mac_table);

	int debug_counter = 0;

	while (1) {
		debug_counter ++;
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
		if (eth_hdr->ethr_type == htons(ETHERTYPE_ARP)) {
			DIE(mac_table_len >= CAPACITY, "Lenght exceeded mac_table_capacity\n");

			printf("We received an ARP packet\n");

			struct arp_hdr *arphdr = (struct arp_hdr*)(buf + sizeof(struct ether_hdr));

			if (arphdr->opcode == ntohs(ARP_REQUEST) || arphdr->opcode == ntohs(ARP_REPLY)) {
				// 	Add the sender. The reply is done automatically by the kernel
				// 	It appears that also the replies by the kernel are detected. Lets not populate our 
				// mac table with our own addresses.
				char cmpbuf[6];
				get_interface_mac(interface, (uint8_t *)cmpbuf);
				if (!memcmp(cmpbuf, arphdr->shwa, 6)) {
					printf("OWN MAC DETECTED. SKIPPING\n");
					continue;
				}
				if (debug_counter % 3 == 0) send_arp_request(interface, arphdr->sprotoa);

				int already_in_table = 0;
				for (int i = 0; i < mac_table_len; i++) {
					if (mac_table[i].ip == arphdr->sprotoa) {
						// Already added. Assume that the mac and IP doesnt change
						// printIp(mac_table[i].ip, "Mac table ip");
						// printIp(arphdr->sprotoa, "Request ip");
						// print_cmp_mac((char *)mac_table[i].mac, (char *)arphdr->shwa, "TABLE | REQ");
						DIE(memcmp(mac_table[i].mac, arphdr->shwa, 6), "MAC OF ONE ENTITY CHANGED (in parsing arp request)\n");
						// Continue if already in table
						already_in_table = 1;
						break;
					}
				}
				if (already_in_table)
					continue;
				// Mac not in table
				mac_table[mac_table_len].ip = arphdr->sprotoa;
				memcpy(mac_table[mac_table_len].mac, arphdr->shwa, 6);
				mac_table_len++;
				// Done parsing. Reply is generated automatically
				print_mac_table_enty();
				printf("Parsed ARP %s. New table length: %d\n", ntohs(arphdr->opcode) == 1 ? "REQUEST" : "REPLY", mac_table_len);
			}

			if (arphdr->opcode != ntohs(ARP_REPLY) && arphdr->opcode != ntohs(ARP_REQUEST)) {
				printf("UNKNOWN ARP OPERATION: %d\n", arphdr->opcode);
			}
		}

    /* Note that packets received are in network order,
		any header field which has more than 1 byte will need to be conerted to
		host order. For example, ntohs(eth_hdr->ether_type). The oposite is needed when
		sending a packet on the link, */


	}
}

