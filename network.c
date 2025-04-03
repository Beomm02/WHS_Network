#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>

#define ETHER_ADDR_LEN 6

// Ethernet 헤더 구조체
struct ethheader {
    u_char ether_dhost[ETHER_ADDR_LEN]; // 목적지 MAC
    u_char ether_shost[ETHER_ADDR_LEN]; // 출발지 MAC
    u_short ether_type;
};

// IP 헤더 구조체
struct ipheader {
    u_char iph_ihl : 4, iph_ver : 4;
    u_char iph_tos;
    u_short iph_len;
    u_short iph_ident;
    u_short iph_offset;
    u_char iph_ttl;
    u_char iph_protocol;
    u_short iph_chksum;
    struct in_addr iph_sourceip;
    struct in_addr iph_destip;
};

// TCP 헤더 구조체
struct tcpheader {
    u_short th_sport;
    u_short th_dport;
    u_int th_seq;
    u_int th_ack;
    u_char th_off : 4, th_res : 4;
    u_char th_flags;
    u_short th_win;
    u_short th_sum;
    u_short th_urp;
};

void got_packet(u_char* args, const struct pcap_pkthdr* header, const u_char* packet) {
    struct ethheader* eth = (struct ethheader*)packet;

    if (ntohs(eth->ether_type) == 0x0800) { // IPv4

        struct ipheader* ip = (struct ipheader*)(packet + sizeof(struct ethheader));

        if (ip->iph_protocol == IPPROTO_TCP) {
            int ip_header_len = ip->iph_ihl * 4;
            struct tcpheader* tcp = (struct tcpheader*)(packet + sizeof(struct ethheader) + ip_header_len);
            int tcp_header_len = tcp->th_off * 4;

            const u_char* payload = packet + sizeof(struct ethheader) + ip_header_len + tcp_header_len;
            int payload_len = header->caplen - (sizeof(struct ethheader) + ip_header_len + tcp_header_len);

            // 출력
            printf("\n[Ethernet] Src MAC: %02x:%02x:%02x:%02x:%02x:%02x -> ",
                eth->ether_shost[0], eth->ether_shost[1], eth->ether_shost[2],
                eth->ether_shost[3], eth->ether_shost[4], eth->ether_shost[5]);
            printf("Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                eth->ether_dhost[0], eth->ether_dhost[1], eth->ether_dhost[2],
                eth->ether_dhost[3], eth->ether_dhost[4], eth->ether_dhost[5]);

            printf("[IP] %s -> %s\n",
                inet_ntoa(ip->iph_sourceip),
                inet_ntoa(ip->iph_destip));

            printf("[TCP] Src Port: %d, Dst Port: %d\n",
                ntohs(tcp->th_sport), ntohs(tcp->th_dport));

            printf("[Message] ");

            for (int i = 0; i < payload_len && i < 32; i++) {
                char c = payload[i];
                printf("%c", isprint(c) ? c : '.');
            }

            printf("  |  ");

            for (int i = 0; i < payload_len && i < 32; i++) {
                printf("%02x ", payload[i]);
            }

            printf("\n");

        }
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t* alldevs;
    pcap_t* handle;

    // 네트워크 장치 목록 가져오기
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        fprintf(stderr, "pcap_findalldevs error: %s\n", errbuf);
        return 1;
    }

    // 첫 번째 장치 선택
    handle = pcap_open_live(alldevs->name, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "pcap_open_live error: %s\n", errbuf);
        return 1;
    }

    printf("\npacket capturing... (Press Ctrl+C)\n");
    pcap_loop(handle, 0, got_packet, NULL);

    // 자원 해제
    pcap_close(handle);
    pcap_freealldevs(alldevs);
    return 0;
}
