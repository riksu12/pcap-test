#ifndef PCAP_TEST_H
#define PCAP_TEST_H
#define ETHERTYPE_IP 0x0800

#include <pcap.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

static inline void print_mac(const uint8_t *mac) {
    printf("%02x:%02x:%02x:%02x:%02x:%02x",
           mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

#pragma pack(push, 1)

struct Eth_Hdr{
    uint8_t dhost[6];
    uint8_t shost[6];
    uint16_t type;
};

struct IP_Hdr{
    uint8_t ipver;
    uint8_t     ip_tos;
    uint16_t    ip_len;
    uint16_t    ip_id;
    uint16_t    ip_off;
    uint8_t     ip_ttl;
    uint8_t     ip_p;
    uint16_t    ip_sum;

    uint32_t sip;
    uint32_t dip;
};

struct TCP_Hdr{
    uint16_t    th_sport;
    uint16_t    th_dport;
    uint32_t th_seq;
    uint32_t th_ack;
    uint8_t th_x2;
    uint8_t th_off;
    uint8_t     th_flags;
    uint16_t    th_win;
    uint16_t    th_sum;
    uint16_t    th_urp;
};

#pragma pack(pop)

#endif // PCAP_TEST_H

