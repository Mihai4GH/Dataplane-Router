#include "protocols.h"
#include "queue.h"
#include "lib.h"
#include <arpa/inet.h>  // For ntohs, ntohl, htons, htonl
#include <string.h>

typedef struct pair {
	struct route_table_entry *route;
	char buf[MAX_PACKET_LEN];
	size_t len;
} pair;

/* Routing table */
struct route_table_entry *rtable;
int rtable_len;

/* Mac table */
#define CAPACITY 100
struct arp_table_entry *mac_table;
int mac_table_len;

/* Package queue */
queue waiting_queue;
queue aux_q;

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

queue scan_queue() {
	while (!queue_empty(waiting_queue)) {
		pair *current = queue_deq(waiting_queue);
		// Check if the ip is in arp cache
		struct arp_table_entry *mac = get_mac_entry(current->route->next_hop);
		if (mac != NULL) {
			// Copy mack to ether frame destination
			struct ether_hdr *eth = (struct ether_hdr *)current->buf; 
			memcpy(eth->ethr_dhost, mac->mac, 6);

			send_to_link(current->len, current->buf, current->route->interface);
			// Free the current element
			free(current);
		} else {
			queue_enq(aux_q, current);
		}
	}
	while (!queue_empty(aux_q)) {
		pair *iter = queue_deq(aux_q);
		queue_enq(waiting_queue, iter);
	}
	return waiting_queue;
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

	// Init the waiting queue
	waiting_queue = create_queue();
	aux_q = create_queue();

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
				get_interface_mac(best_route->interface, eth_hdr->ethr_shost);
				send_arp_request(best_route->interface, best_route->next_hop);
				// Enqueue the current package
				pair *q_pair = calloc(1, sizeof(pair));
				memcpy(q_pair->buf, buf, MAX_PACKET_LEN);
				q_pair->route = best_route;
				q_pair->len = len;
				queue_enq(waiting_queue, q_pair);
				// Done enquing
				continue;
			}
			memcpy(eth_hdr->ethr_dhost, mac_entry->mac, 6);
			get_interface_mac(best_route->interface, eth_hdr->ethr_shost);
			send_to_link(len, buf, best_route->interface);
		}

		// ARP PROTOCOL
		if (eth_hdr->ethr_type == htons(ETHERTYPE_ARP)) {
			DIE(mac_table_len >= CAPACITY, "Lenght exceeded mac_table_capacity\n");

			struct arp_hdr *arphdr = (struct arp_hdr*)(buf + sizeof(struct ether_hdr));

			printf("We received an ARP packet, OPCODE = %d, REQ = %d\n", arphdr->opcode, htons(ARP_REQUEST));

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
				print_mac_table_enty();

				if (arphdr->opcode == ntohs(ARP_REQUEST)) {
					uint32_t my_interface_ip = ntohl(ip_to_int(get_interface_ip(interface)));
					// printIp(arphdr->tprotoa, "Arp req ip");
					// printIp(my_interface_ip, "My ip");

					if (arphdr->tprotoa != my_interface_ip)
						continue;

					printf("Request received. Sending reply\n");
					char *reply = calloc(1, 1500);
					memcpy(reply, buf, len);
					struct ether_hdr* reply_eth = (struct ether_hdr *)reply;
					struct arp_hdr* reply_arp = (struct arp_hdr *)(reply + sizeof(struct ether_hdr));
					memcpy(reply_eth->ethr_dhost, reply_eth->ethr_shost, 6);
					get_interface_mac(interface, reply_eth->ethr_shost);

					memcpy(reply_arp->thwa, reply_eth->ethr_dhost, 6);
					memcpy(reply_arp->shwa, reply_eth->ethr_shost, 6);

					reply_arp->tprotoa = reply_arp->sprotoa;
					reply_arp->sprotoa = my_interface_ip;

					reply_arp->opcode = htons(ARP_REPLY);
					print_cmp_mac((char *)reply_eth->ethr_shost, (char *)reply_arp->shwa, "from\t");
					print_cmp_mac((char *)reply_eth->ethr_dhost, (char *)reply_arp->thwa, "to\t");
					printIp(reply_arp->sprotoa, "sender");
					printIp(reply_arp->tprotoa, "target");
					int len_reply = 0;
					while (len_reply < len) {
						len_reply += send_to_link(len-len_reply, reply, interface);
						printf("len_reply %d\n", len_reply);
					}
					printf("Sent\n\n");
					free(reply);
				}

				if (already_in_table)
					continue;
				// Mac not in table
				mac_table[mac_table_len].ip = arphdr->sprotoa;
				memcpy(mac_table[mac_table_len].mac, arphdr->shwa, 6);
				mac_table_len++;

				waiting_queue = scan_queue();

				// Done parsing. Reply is generated automatically
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

