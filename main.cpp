#include <pcap.h>
#include <stdio.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <net/ethernet.h>
void dump(const u_char *p, int len) {
	for (int i = 0; i < len; i++) {
		printf("%02x ", p[i]);
		if ((i & 0x0f) == 0x0f) printf("\n");
	}
	printf("\n");
}

void print_address(const u_char *p, int base_offset, int len) {
	if (len == 6) {
		for (int i = 0; i < len; i++) {
			if (i) printf(":");
			printf("%02X", p[base_offset + i]);
		}
	}
	else if (len == 4) {
		for (int i = 0; i < len; i++) {
			if (i) printf(".");
			printf("%02d", p[base_offset + i]);
		}
	}
	else {
		printf("%d", p[base_offset] * 256 + p[base_offset + 1]);
	}
}

void parsing_packet(const u_char *p, int len){
	struct ether_header *ep = (struct ether_header *)p;

	struct ip *iph = (struct ip *)(p + sizeof(struct ether_header));
	struct tcphdr *tcph = (struct tcphdr *)(p + sizeof(struct ether_header) + iph->ip_hl * 4);

	const int ethernet_base = 0;
	const int ethernet_Source_offset = 6;
	const int ethernet_Destination_offset = 0;
	const int ethernet_address_size = 6;
	
	const int ip_base = sizeof(struct ether_header);
	const int ip_Source_offset = 12;
	const int ip_Destination_offset = 16;
	const int ip_address_size = 4;

	const int tcp_base = ip_base + iph->ip_hl * 4;
	const int tcp_Source_offset = 0;
	const int tcp_Destination_offset = 2;
	const int tcp_address_size = 2;

	printf("Ethernet Source Address : ");
	print_address(p, ethernet_base + ethernet_Source_offset, ethernet_address_size);

	printf("\nEthernet Destination Address : ");
	print_address(p, ethernet_base + ethernet_Destination_offset, ethernet_address_size);

	printf("\n\n");

	printf("IP Source Address : ");
	print_address(p, ip_base + ip_Source_offset, ip_address_size);
	
	printf("\nIP Destination Address : ");
	print_address(p, ip_base + ip_Destination_offset, ip_address_size);

	printf("\n\n");
	printf("TCP Source Address : ");
	print_address(p, tcp_base + tcp_Source_offset, tcp_address_size);
	
	printf("\nTCP Destination Address : ");
	print_address(p, tcp_base + tcp_Destination_offset, tcp_address_size);

	printf("\n\n");

	int data_size = (len - sizeof(struct ether_header) - iph->ip_hl * 4 - tcph->th_off < 32) ? len - sizeof(struct ether_header) - iph->ip_hl * 4 - tcph->th_off : 32;
	printf("data : ");
	dump(p + sizeof(struct ether_header) + iph->ip_hl * 4 + tcph->th_off, data_size);
}

bool check_IPv4_TCP(const u_char *p, int len){
	struct ether_header *ep = (struct ether_header *)p;
	if (ntohs(ep->ether_type) != ETHERTYPE_IP) return 0;
	p += sizeof(struct ether_header);

	struct ip *iph = (struct ip *)p;
	if (iph->ip_p != IPPROTO_TCP) return 0;
	
	return 1;
}
void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}

int main(int argc, char* argv[]) {
  if (argc != 2) {
    usage();
    return -1;
  }

  char* dev = argv[1];
  char errbuf[PCAP_ERRBUF_SIZE];
  pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
  if (handle == NULL) {
    fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
    return -1;
  }

  while (true) {
    struct pcap_pkthdr* header;
    const u_char* packet;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    printf("%u bytes captured\n", header->caplen);
	if(check_IPv4_TCP(packet, header->len))	parsing_packet(packet, header->caplen);
  }

  pcap_close(handle);
  return 0;
}

