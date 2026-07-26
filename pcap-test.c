#include <pcap.h>
#include <stdbool.h>
#include <stdio.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <libnet.h>

#ifndef ETHERTYPE_IP
#define ETHERTYPE_IP 0x0800
#endif

void usage() {
    printf("syntax: pcap-test <interface>\n");
    printf("sample: pcap-test eth0\n");
}

typedef struct {
    char* dev_;
} Param;

Param param = {
    .dev_ = NULL
};

bool parse_args(Param* param, int argc, char* argv[]) {
    if (argc != 2) {
        usage();
        return false;
    }
    param->dev_ = argv[1];
    return true;
}

void print_mac(const u_char* mac) { //MAC print
    printf("%02x:%02x:%02x:%02x:%02x:%02x", mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

// Ethernet
bool parse_ethernet(const u_char* packet) { 
    struct libnet_ethernet_hdr* eth_h = (struct libnet_ethernet_hdr*)packet;
    if (ntohs(eth_h->ether_type) != ETHERTYPE_IP) {
        return false;
    }

    printf("[Ethernet Header]\n");
    printf("Src MAC: "); print_mac(eth_h->ether_shost); printf("\n");
    printf("Dst MAC: "); print_mac(eth_h->ether_dhost); printf("\n");
    return true;
}

// IP
int parse_ip(const u_char* packet, int* ip_header_len) {
    struct libnet_ipv4_hdr* ip_h = (struct libnet_ipv4_hdr*)(packet + sizeof(struct libnet_ethernet_hdr));
    if (ip_h->ip_p != IPPROTO_TCP) {
        return -1;
    }

    printf("[IP Header]\n");
    printf("Src IP: %s\n", inet_ntoa(ip_h->ip_src));
    printf("Dst IP: %s\n", inet_ntoa(ip_h->ip_dst));

    *ip_header_len = ip_h->ip_hl * 4;
    return 0;
}

// TCP
int parse_tcp(const u_char* packet, int ip_header_len, int* tcp_header_len) {
    struct libnet_tcp_hdr* tcp_h = (struct libnet_tcp_hdr*)(packet + sizeof(struct libnet_ethernet_hdr) + ip_header_len);

    printf("[TCP Header]\n");
    printf("Src Port: %u\n", ntohs(tcp_h->th_sport));
    printf("Dst Port: %u\n", ntohs(tcp_h->th_dport));

    *tcp_header_len = tcp_h->th_off * 4;
    return 0;
}

// Payload
void parse_payload(const u_char* packet, struct pcap_pkthdr* header, int ip_header_len, int tcp_header_len) {
    int total_header_len = sizeof(struct libnet_ethernet_hdr) + ip_header_len + tcp_header_len;
    int payload_len = header->caplen - total_header_len;

    printf("[Payload / Data]\n");
    if (payload_len > 0) {
        const u_char* payload = packet + total_header_len;
        printf("Payload length: %d bytes\n", payload_len);
        printf("Data (Hex): ");
        for (int i = 0; i < payload_len && i < 20; i++) {
            printf("%02x ", payload[i]);
        }
        printf("\n");
    } else {
        printf("No payload data.\n");
    }
}

int main(int argc, char* argv[]) {
    if (!parse_args(&param, argc, argv))
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
        parse_tcp(packet, ip_header_len, &tcp_header_len);

        parse_payload(packet, header, ip_header_len, tcp_header_len);
    }

    pcap_close(pcap);
    return 0;   
}
