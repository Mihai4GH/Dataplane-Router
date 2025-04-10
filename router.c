#include "protocols.h"
#include "queue.h"
#include "lib.h"
#include <arpa/inet.h>  // For ntohs, ntohl, htons, htonl
#include <string.h>

/* Pair to store information in queue */
typedef struct pair {
	struct route_table_entry *route;
	char buf[MAX_PACKET_LEN];
	size_t len;
} pair;

/* Routing table */
struct route_table_entry *rtable;
int rtable_len;

/* Trie */
struct trie_node *root;

/* Mac table */
#define CAPACITY 100
struct arp_table_entry *mac_table;
int mac_table_len;

/* Package queue */
queue waiting_queue;
/* Auxiliar queue used for processing elements of waiting_queue */
queue aux_q;

// Debugg Function - All on network order

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

// Trie implementation starts here
struct trie_node {
    struct route_table_entry *entry;
    struct trie_node *children[2];    
};

struct trie_node *create_node() {
    struct trie_node *node = (struct trie_node *)malloc(sizeof(struct trie_node));
    if (node) {
        node->entry = NULL;
        node->children[0] = NULL;
        node->children[1] = NULL;
    }
    return node;
}

void insert_route(struct trie_node *root, struct route_table_entry *route) {
    struct trie_node *current = root;
    uint32_t prefix = ntohl(route->prefix);
    uint32_t mask = ntohl(route->mask);
    
    // Calculate the prefix length from the mask
    int prefix_length = 0;
    uint32_t temp_mask = mask;
    while (temp_mask) {
        prefix_length += (temp_mask & 1);
        temp_mask >>= 1;
    }
    
    // Start from the most significant bit of the prefix
    for (int i = 31; i >= 32 - prefix_length; i--) {
        int bit = (prefix >> i) & 1;
        
        if (!current->children[bit]) {
            current->children[bit] = create_node();
        }
        
        current = current->children[bit];
    }
    
    // Store the route at the appropriate node
    current->entry = route;
}

struct trie_node *build_trie(struct route_table_entry *rtable, int rtable_len) {
    struct trie_node *root = create_node();
    
    for (int i = 0; i < rtable_len; i++) {
        insert_route(root, &rtable[i]);
    }
    
    return root;
}

struct route_table_entry *get_best_route_trie(uint32_t ip) {
	printf("Trie lookup...\n");
    struct trie_node *current = root;
    struct route_table_entry *best_match = NULL;

	ip = ntohl(ip);

    // Traverse the trie from most significant bit to least significant bit
    for (int i = 31; i >= 0; i--) {
        int bit = (ip >> i) & 1;
        
        if (!current->children[bit]) {
            break; // No matching path
        }
        
        current = current->children[bit];
        
        // If there's an entry at this node, it's a potential match
        if (current->entry) {
            // We're already traversing in order of longest prefix, so any match is better than previous ones
            best_match = current->entry;
        }
    }
    
    return best_match;
}
// 	Trie implementation ends here. No need for delete functions, as the trie exists
// for as long as the router is up.

struct arp_table_entry* get_mac_entry(uint32_t given_ip) {
	for (int i = 0; i < mac_table_len; i++) {
		if (mac_table[i].ip == given_ip) {
			return &mac_table[i];
		}
	}
	return NULL;
}

unsigned int ip_to_int(char *ip_str)
{
    struct in_addr addr;
    inet_pton(AF_INET, ip_str, &addr);  // Convert IP string to binary format
    return ntohl(addr.s_addr);          // Convert to host order
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
			// Remove from queue and free the current element
			free(current);
		} else {
			// Store the elements that cant be forwarded
			queue_enq(aux_q, current);
		}
	}
	// Rebuild the queue
	while (!queue_empty(aux_q)) {
		pair *iter = queue_deq(aux_q);
		queue_enq(waiting_queue, iter);
	}
	return waiting_queue;
}

void echo_reply(char *buf, size_t len, size_t ineterface, char type, char code) {
	struct ether_hdr *eth_hdr = (struct ether_hdr *)buf;
	
	// Sender back
	memcpy(eth_hdr->ethr_dhost, eth_hdr->ethr_shost, 6);
	get_interface_mac(ineterface, eth_hdr->ethr_shost);

	struct ip_hdr* ip_hdr = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
	ip_hdr->ttl = 64;
	ip_hdr->dest_addr = ip_hdr->source_addr;
	ip_hdr->source_addr = ntohl(ip_to_int(get_interface_ip(ineterface)));
	ip_hdr->checksum = 0;
	ip_hdr->checksum = htons(checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr)));

	struct icmp_hdr* icmp_hdr = (struct icmp_hdr *)(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
	icmp_hdr->mtype = type;
	icmp_hdr->mcode = code;
	icmp_hdr->check = 0;

	icmp_hdr->check = htons(checksum((uint16_t *)(buf + sizeof(struct ether_hdr) + sizeof(struct ip_hdr)),
									 ntohs(ip_hdr->tot_len) - sizeof(struct ip_hdr)));

	send_to_link(len, buf, ineterface);
}

// Build and send an ICMP package (either ttl reach 0 or host unreachable)
void echo_reply_error(char *buf, size_t len, size_t interface, char type, char code) {
	char resp[256] = {0};

	struct ether_hdr *eth = (struct ether_hdr *)resp;
	struct ether_hdr *old_eth = (struct ether_hdr *)buf;
	memcpy(eth->ethr_dhost, old_eth->ethr_shost, 6);
	memcpy(eth->ethr_shost, old_eth->ethr_dhost, 6);
	eth->ethr_type = old_eth->ethr_type;

	struct ip_hdr *ip = (struct ip_hdr *)(resp + sizeof(struct ether_hdr));
	struct ip_hdr *old_ip = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));

	ip->dest_addr = old_ip->source_addr;
	ip->source_addr = htonl(ip_to_int(get_interface_ip(interface)));
	ip->checksum = 0;
	ip->ttl = 64;
	ip->frag = 0;
	ip->id = 4;
	ip->tos = 0;
	ip->ihl = 5;
	ip->ver = 4;
	ip->proto = IPPROTO_ICMP;
	ip->tot_len = htons((2*sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + 64));

	ip->checksum = htons(checksum((uint16_t *)ip, sizeof(struct ip_hdr)));

	struct icmp_hdr *icmp = (struct icmp_hdr *)(resp + sizeof(struct ether_hdr) + sizeof(struct ip_hdr));
	icmp->check = 0;
	icmp->mtype = type;
	icmp->mcode = code;
	icmp->un_t.echo_t.id = 0;
	icmp->un_t.echo_t.seq = 0;

	memcpy((char *)(icmp+1), (char *)old_ip, sizeof(struct ip_hdr) + 64);
	icmp->check = htons(checksum((uint16_t *)icmp, sizeof(struct ip_hdr) + sizeof(struct icmp_hdr) + 64));


	size_t lenght = sizeof(struct ether_hdr) + sizeof(struct ip_hdr) * 2 + sizeof(struct icmp_hdr) + 64;
	send_to_link(lenght, resp, interface);
	return;
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
	// Build the trie
	root = build_trie(rtable, rtable_len);

	// Read static MAC
	mac_table = malloc(sizeof(struct arp_table_entry) * CAPACITY);
	DIE(mac_table == NULL, "Failed malloc\n");
	mac_table_len = 0;

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

		uint8_t cmp_buf[6] = {0};
		get_interface_mac(interface, cmp_buf);
		// If this package was sent by the router skip it.
		if (!strcmp((const char*)cmp_buf, (const char*)eth_hdr->ethr_shost)) {
			printf("Package sent by own self detected. Skipping...\n");
			continue;
		} 
		
		if (eth_hdr->ethr_type == ntohs(ETHERTYPE_IP)) {
			// We have an ip_package
			printf("We've received an IP package\n");

			struct ip_hdr *ip_hdr = (struct ip_hdr *)(buf + sizeof(struct ether_hdr));
			
			uint16_t check = ntohs(ip_hdr->checksum);
			ip_hdr->checksum = 0;
			// Checksum
			if (check != checksum((uint16_t *)ip_hdr, sizeof(struct ip_hdr))) {
				printf("IP checksum failed. Dropping packet...\n");
				continue;
			}
			// Ping request
			if (ip_hdr->dest_addr == htonl(ip_to_int(get_interface_ip(interface))) && ip_hdr->proto == IPPROTO_ICMP) {
				// We received an echo request destinated to us
				echo_reply(buf, len, interface, 0, 0);
				printf("Icmp echo reply ongoing...\n");
				continue;
			}
			// Check ttl
			if (ip_hdr->ttl <= 1) {
				printf("TTL reached 0\n");
				echo_reply_error(buf, len, interface, 11, 0);
				continue;
			}
			ip_hdr->ttl--;

			struct route_table_entry *best_route = get_best_route_trie(ip_hdr->dest_addr);

			if (!best_route) {
				printf("Destination host unreachable!\n");
				echo_reply_error(buf, len, interface, 3, 0);
				continue;
			} else {
				printf("Recognized ip\n");
			}

			ip_hdr->checksum = 0;
			ip_hdr->checksum = htons(checksum((u_int16_t *)ip_hdr, sizeof(struct ip_hdr)));

			struct arp_table_entry *mac_entry = get_mac_entry(best_route->next_hop);
			if (mac_entry == NULL) {
				// Send arp request
				get_interface_mac(best_route->interface, eth_hdr->ethr_shost);
				send_arp_request(best_route->interface, best_route->next_hop);
				// Enqueue the current package
				pair *q_pair = calloc(1, sizeof(pair));
				memcpy(q_pair->buf, buf, MAX_PACKET_LEN);
				q_pair->route = best_route;
				q_pair->len = len;
				queue_enq(waiting_queue, q_pair);
				// Process next packets
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
						DIE(memcmp(mac_table[i].mac, arphdr->shwa, 6), "MAC OF ONE ENTITY CHANGED (in parsing arp request)\n");
						// Continue if already in table
						already_in_table = 1;
						break;
					}
				}
				print_mac_table_enty();

				if (arphdr->opcode == ntohs(ARP_REQUEST)) {
					uint32_t my_interface_ip = ntohl(ip_to_int(get_interface_ip(interface)));

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
					int len_reply = 0;
					while (len_reply < len) {
						len_reply += send_to_link(len-len_reply, reply, interface);
					}
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

