#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <pcap-test.h>
#include <arpa/inet.h>

void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

typedef struct {
	char* dev_;
} Param;

Param param = {
	.dev_ = NULL
};

bool parse(Param* param, int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	param->dev_ = argv[1];
	return true;
}

//Ethernet
bool parse_ethernet(const u_char* packet){
    struct Eth_Hdr* L2 = (struct Eth_Hdr*)packet;

    if(ntohs(L2->type) != ETHERTYPE_IP) return false;

    printf("<<<Ethernet>>>\n");
    printf("src mac: "); print_mac(L2->shost); printf("\n");
    printf("dst mac: "); print_mac(L2->dhost); printf("\n");

    return true;
}

// IP
int parse_ip(const u_char* packet, int* ip_header_len) {
    struct IP_Hdr* ip_h = (struct IP_Hdr*)(packet + sizeof(struct Eth_Hdr));

    if (ip_h->ip_p != 6) {
        return -1;
    }

    printf("<<<IP Header>>>\n");

    struct in_addr src_addr, dst_addr;
    src_addr.s_addr = ip_h->sip;
    dst_addr.s_addr = ip_h->dip;

    printf("Src IP: %s\n", inet_ntoa(src_addr));
    printf("Dst IP: %s\n", inet_ntoa(dst_addr));

    *ip_header_len = (ip_h->ipver & 0x0F) * 4;
    return 0;
}

// TCP
int parse_tcp(const u_char* packet, int ip_header_len, int* tcp_header_len) {
    struct TCP_Hdr* tcp_h = (struct TCP_Hdr*)(packet + sizeof(struct Eth_Hdr) + ip_header_len);

    printf("<<<TCP Header>>>\n");
    printf("Src Port: %u\n", ntohs(tcp_h->th_sport));
    printf("Dst Port: %u\n", ntohs(tcp_h->th_dport));

    *tcp_header_len = ((tcp_h->th_off >> 4) & 0x0F) * 4;
    return 0;
}

// Payload
void parse_payload(const u_char* packet, struct pcap_pkthdr* header, int ip_header_len, int tcp_header_len) {
    int total_header_len = sizeof(struct Eth_Hdr) + ip_header_len + tcp_header_len;
    int payload_len = header->caplen - total_header_len;

    printf("<<<Payload / Data>>>\n");
    if (payload_len > 0) {
        const u_char* payload = packet + total_header_len;
        printf("Payload length: %d bytes\n", payload_len);
        printf("Data (Hex): ");

        for (int i = 0; i < payload_len && i < 16; i++) {
            printf("%02x ", payload[i]);
        }
        printf("\n");
    } else {
        printf("No payload data.\n");
    }
}

int main(int argc, char* argv[]) {
	if (!parse(&param, argc, argv))
		return -1;

	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

	while (true) {
		struct pcap_pkthdr* header;
		const u_char* packet;
		int res = pcap_next_ex(pcap, &header, &packet);
		if (res == 0) continue;
		if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
			printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
			break;
		}
		printf("%u bytes captured\n", header->caplen);

        if (!parse_ethernet(packet)) continue;

        int ip_header_len = 0;
        if (parse_ip(packet, &ip_header_len) < 0) continue;

        int tcp_header_len = 0;
        if (parse_tcp(packet, ip_header_len, &tcp_header_len) < 0) continue;

        parse_payload(packet, header, ip_header_len, tcp_header_len);
	}

	pcap_close(pcap);
    return 0;
}
