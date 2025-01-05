#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <errno.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <sys/socket.h>
#include <sys/types.h>

#define UE_IP_PCAP "21.0.0.14"
#define UE_IP "33.172.0.1"

#define ENB_IP "10.101.11.2"
#define ENB_PORT 2152

#define UPF_ENB_IP "10.201.11.3"
#define UPF_ENB_PORT 2152

#define UPF_DN_IP "10.0.3.3"
#define UPF_DN_UDP_PORT 23012

#define DN_IP "10.40.93.2"
#define DN_UDP_PORT 23016

#define UDP_NUMBER 17
#define TCP_NUMBER 6

#define VERSION_FLAG 0x30
#define MESSAGE_TYPE 0xFF
#define TEID 268435457

#define ETH_HDR_LEN 14
#define IP_HDR_LEN 20
#define UDP_HDR_LEN 8
#define GTPU_HDR_LEN 8
#define MIN_TCP_HDR_LEN 20
#define VLAN_TAG 0x8100
#define VLAN_TAG_LEN 4
#define GLB_HDR_LEN 24
#define PKT_HDR_LEN 16
#define BUFFSIZE 65535
#define MAX_BYTE 1436

uint16_t ue_port = 0;

uint16_t ip_checksum(uint16_t *buf, int nwords) {
    uint32_t sum = 0;
    int i = 0;
    for (i = 0; i < nwords; i++) {
        sum += buf[i];
    }
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (uint16_t)(~sum);
}

void modify_pkt(uint8_t *packet, int packet_len, uint8_t *out_pkt, int *out_pkt_len) {
    struct iphdr *ip_hdr = (struct iphdr *)packet;
    if (strcmp(inet_ntoa(*(struct in_addr *)&ip_hdr->saddr), UE_IP_PCAP) == 0) {
        ip_hdr->saddr = inet_addr(UE_IP);
        ip_hdr->daddr = inet_addr(DN_IP);
        ip_hdr->check = 0;
        ip_hdr->check = ip_checksum((uint16_t *)ip_hdr, IP_HDR_LEN / 2);
        struct udphdr *udp_hdr = (struct udphdr *)(packet + IP_HDR_LEN);
        if (ip_hdr->protocol == UDP_NUMBER) {
            udp_hdr->dest = htons(DN_UDP_PORT);
            udp_hdr->check = 0;
            memcpy(out_pkt, packet, packet_len);
            *out_pkt_len = packet_len;
        } else if (ip_hdr->protocol == TCP_NUMBER) {
            
        }
    } else {
        ue_port = ntohs(*(uint16_t *)(packet + IP_HDR_LEN + 2));
        memcpy(out_pkt, packet + IP_HDR_LEN, packet_len - IP_HDR_LEN);
        *out_pkt_len = packet_len - IP_HDR_LEN;
    }
}

void create_gtpu_packet(uint8_t *packet, int packet_len, uint8_t *gtpu_packet, int *gtpu_packet_len) {
    uint8_t modified_packet[BUFFSIZE];
    int modified_packet_len;
    modify_pkt(packet, packet_len, modified_packet, &modified_packet_len);
    struct {
        uint8_t flags;
        uint8_t type;
        uint16_t len;
        uint32_t teid;
    } __attribute__((__packed__)) gtpu_hdr;
    gtpu_hdr.flags = VERSION_FLAG;
    gtpu_hdr.type = MESSAGE_TYPE;
    gtpu_hdr.len = htons(modified_packet_len);
    gtpu_hdr.teid = htonl(TEID);
    memcpy(gtpu_packet, &gtpu_hdr, sizeof(gtpu_hdr));
    memcpy(gtpu_packet + sizeof(gtpu_hdr), modified_packet, modified_packet_len);
    *gtpu_packet_len = sizeof(gtpu_hdr) + modified_packet_len;
}

void remove_ethernet_header(uint8_t *packet, int packet_len, uint8_t **payload, int *payload_len) {
    uint16_t eth_type = ntohs(*(uint16_t *)(packet + ETH_HDR_LEN - 2));
    if (eth_type == VLAN_TAG) {
        *payload = packet + ETH_HDR_LEN + VLAN_TAG_LEN;
        *payload_len = packet_len - (ETH_HDR_LEN + VLAN_TAG_LEN);
    } else {
        *payload = packet + ETH_HDR_LEN;
        *payload_len = packet_len - ETH_HDR_LEN;
    }
}

void process_pcap(const char *pcap_file) {
    struct sockaddr_ll sa;
    struct ifreq ifr;
    const char *if_name = "p1p2";
    char buffer[65535];

    int enb_s1u_n3 = socket(AF_INET, SOCK_DGRAM, 0);
    struct sockaddr_in enb_addr = {
        .sin_family = AF_INET,
        .sin_port = htons(ENB_PORT),
        .sin_addr.s_addr = inet_addr(ENB_IP),
    };
    bind(enb_s1u_n3, (struct sockaddr *)&enb_addr, sizeof(enb_addr));

    int dn_sgi_n6 = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, "if_name", IFNAMSIZ);
    if(ioctl(dn_sgi_n6, SIOCGIFINDEX, &ifr) < 0) {
        perror("Unable to get interface index");
        exit(EXIT_FAILURE);
    }
    memset(&sa, 0, sizeof(sa));
    sa.ss_index = ifr.ifr_ifindex;
    sa.ss_protocol = htons(ETH_P_ALL);
    if(bind(dn_sgi_n6, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("Unable to bind interface");
        close(dn_sgi_n6);
        exit(EXIT_FAILURE);
    }

    FILE *f = fopen(pcap_file, "rb");
    fseek(f, GLB_HDR_LEN, SEEK_SET);
    int idx = 0;
    while (1) {
        uint8_t packet[BUFFSIZE];
        if (fread(packet, 1, PKT_HDR_LEN, f) != PKT_HDR_LEN) break;
        struct {
            uint32_t ts_sec;
            uint32_t ts_usec;
            uint32_t incl_len;
            uint32_t orig_len;
        } __attribute__((__packed__)) pkt_hdr;
        memcpy(&pkt_hdr, packet, PKT_HDR_LEN);
        fread(packet, 1, pkt_hdr.incl_len, f);
        uint8_t *payload;
        int payload_len;
        remove_ethernet_header(packet, pkt_hdr.incl_len, &payload, &payload_len);
        struct iphdr *ip_hdr = (struct iphdr *)payload;
        if (strcmp(inet_ntoa(*(struct in_addr *)&ip_hdr->saddr), UE_IP_PCAP) == 0) {
            uint8_t gtpu_packet[BUFFSIZE];
            int gtpu_packet_len;
            create_gtpu_packet(payload, payload_len, gtpu_packet, &gtpu_packet_len);
            sendto(enb_s1u_n3, gtpu_packet, gtpu_packet_len, 0, (struct sockaddr *)&(struct sockaddr_in) {
                .sin_family = AF_INET,
                .sin_port = htons(UPF_ENB_PORT),
                .sin_addr.s_addr = inet_addr(UPF_ENB_IP),
            }, sizeof(struct sockaddr_in));
            printf("ID: %d - ENB: Sent packet to UPF.\n", idx);
           
            int ret = recv(dn_sgi_n6, buffer, sizeof(buffer), 0);
            if(ret < 0) {
                perror("Unable to receive packet");
                close(dn_sgi_n6);
                exit(EXIT_FAILURE);
            }
            printf("ID: %d - DN UDP: Received an IP packet uplink from UPF.\n", idx);
        } else {
            uint8_t modified_packet[BUFFSIZE];
            int modified_packet_len;
            modify_pkt(payload, payload_len, modified_packet, &modified_packet_len);
            sendto(dn_sgi_n6, modified_packet, modified_packet_len, 0, (struct sockaddr *)&(struct sockaddr_in) {
                .sin_family = AF_INET,
                .sin_port = htons(ue_port),
                .sin_addr.s_addr = inet_addr(UE_IP),
            }, sizeof(struct sockaddr_in));
            printf("ID: %d - DN UDP: Sent packet to UPF.\n", idx);
            recvfrom(enb_s1u_n3, packet, BUFFSIZE, 0, NULL, NULL);
            printf("ID: %d - ENB: Received a GTP-u packet downlink from UPF.\n", idx);
        }
        idx++;
    }
    fclose(f);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "Usage: %s <pcap_file>\n", argv[0]);
        exit(EXIT_FAILURE);
    }
    process_pcap(argv[1]);
    return 0;
} 