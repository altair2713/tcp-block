#include <cstdio>
#include <pcap.h>
#include <libnet.h>
#include <string>
#define SUCCESS 0
#define FAIL -1
typedef struct libnet_ethernet_hdr ETH_HDR;
typedef struct libnet_ipv4_hdr IP_HDR;
typedef struct libnet_tcp_hdr TCP_HDR;
typedef struct packet_header {
    ETH_HDR eth;
    IP_HDR ip;
    TCP_HDR tcp;
    std::string data;
}packet;
uint8_t my_mac[6];
uint8_t pattern[1024];
uint32_t pattern_length;
packet forward,backward;
char* strnstr(uint8_t* big, uint8_t* little, uint32_t len)
{
    uint32_t i,temp;
    i=0;
    while(big[i]&&i<len) {
        temp=0;
        if(little[temp]==big[i+temp]) {
            while(little[temp]&&big[i+temp]) {
                if(little[temp]!=big[i+temp]||(i+temp)>=len) break;
                temp++;
            }
            if(little[temp]=='\0') return (&((char *)big)[i]);
        }
        i++;
    }
    return (NULL);
}
int get_my_mac(char* dev)
{
    struct ifreq ifr;
    int sockfd=socket(AF_INET, SOCK_DGRAM, 0);
    if(sockfd<0) {
        printf("Failed to get attacker's MAC! (reason : socket() failed)\n");
        return FAIL;
    }
    ifr.ifr_addr.sa_family=AF_INET;
    strncpy(ifr.ifr_name, dev, IFNAMSIZ-1);
    int ret=ioctl(sockfd, SIOCGIFHWADDR, &ifr);
    if(ret<0) {
        printf("Failed to get attacker's MAC! (reason : ioctl() failed)\n");
        close(sockfd);
        return FAIL;
    }
    memcpy(my_mac, ifr.ifr_hwaddr.sa_data, 6);
    close(sockfd);
    return SUCCESS;
}
uint16_t checksum(uint16_t sum, const void* header, uint32_t len)
{
    uint32_t cnt=(uint32_t)sum;
    uint16_t* header_16=(uint16_t*)header;
    for(uint32_t i = 0; i < len/2; i++) {
        cnt+=(uint32_t)ntohs(header_16[i]);
        while(cnt>0xffff) cnt=(cnt>>16)+(cnt&0xffff);
    }
    if(len&1) cnt+=(uint32_t)ntohs(header_16[len/2]);
    while(cnt>0xffff) cnt=(cnt>>16)+(cnt&0xffff);
    return (uint16_t)cnt;
}
uint16_t tcp_checksum(packet_header* packet)
{
    uint16_t sum;
    packet->tcp.th_sum=0;
    uint16_t header[6];
    memset(header,0,sizeof(header));
    memcpy(header,&packet->ip.ip_src,4);
    memcpy(&header[2],&packet->ip.ip_dst,4);
    header[4]=packet->ip.ip_p;
    header[4]=htons(header[4]);
    header[5]=htons(ntohs(packet->ip.ip_len)-(packet->ip.ip_hl<<2));
    sum=checksum(0,header,12);
    sum=checksum(sum,&packet->tcp,sizeof(TCP_HDR));
    if(packet->data.size()) sum=checksum(sum,packet->data.c_str(),packet->data.size());
    return ~sum;
}
void make_tcp_hdr(TCP_HDR* packet_tcp, uint32_t packet_len)
{
    memcpy(&forward.tcp,packet_tcp,sizeof(TCP_HDR));
    memcpy(&backward.tcp,packet_tcp,sizeof(TCP_HDR));
    std::swap(backward.tcp.th_sport,backward.tcp.th_dport);
    forward.tcp.th_seq=htonl(ntohl(packet_tcp->th_seq)+packet_len);
    backward.tcp.th_seq=htonl(ntohl(packet_tcp->th_seq)+packet_len);
    std::swap(backward.tcp.th_ack,backward.tcp.th_seq);
    forward.tcp.th_off=sizeof(TCP_HDR)>>2;
    backward.tcp.th_off=sizeof(TCP_HDR)>>2;
    forward.tcp.th_flags=TH_ACK;
    backward.tcp.th_flags=TH_ACK;
    forward.tcp.th_flags|=TH_RST;
    backward.tcp.th_flags|=TH_FIN;
    backward.data="HTTP/1.0 302 Redirect\r\nLocation: http://warning.or.kr\r\n";
    return;
}
void make_ip_hdr(IP_HDR* packet_ip)
{
    memcpy(&forward.ip,packet_ip,sizeof(IP_HDR));
    memcpy(&backward.ip,packet_ip,sizeof(IP_HDR));
    forward.ip.ip_len=htons(sizeof(IP_HDR)+sizeof(TCP_HDR));
    backward.ip.ip_len=htons(sizeof(IP_HDR)+sizeof(TCP_HDR)+backward.data.length());
    backward.ip.ip_ttl=128;
    std::swap(backward.ip.ip_src,backward.ip.ip_dst);
    forward.ip.ip_sum=0;
    forward.ip.ip_sum=~htons(checksum(0,&forward.ip,sizeof(IP_HDR)));
    backward.ip.ip_sum=0;
    backward.ip.ip_sum=~htons(checksum(0,&backward.ip,sizeof(IP_HDR)));
    return;
}
void make_eth_hdr(ETH_HDR* packet_eth)
{
    for(int i = 0; i < 6; i++) {
        forward.eth.ether_shost[i]=my_mac[i];
        backward.eth.ether_shost[i]=my_mac[i];
        forward.eth.ether_dhost[i]=packet_eth->ether_dhost[i];
        backward.eth.ether_dhost[i]=packet_eth->ether_shost[i];
    }
    forward.eth.ether_type=htons(ETHERTYPE_IP);
    backward.eth.ether_type=htons(ETHERTYPE_IP);
    return;
}
void send_packet(pcap_t* handle, packet_header* packet)
{
    uint32_t ip_offset=sizeof(packet->eth);
    uint32_t tcp_offset=ip_offset+sizeof(packet->ip);
    uint32_t data_offset=tcp_offset+sizeof(packet->tcp);
    uint32_t packet_length=data_offset+packet->data.size();
    uint8_t* send_packet=(uint8_t*)malloc(packet_length);
    memcpy(send_packet,&packet->eth,sizeof(packet->eth));
    memcpy(&send_packet[ip_offset],&packet->ip,sizeof(packet->ip));
    memcpy(&send_packet[tcp_offset],&packet->tcp,sizeof(packet->tcp));
    if(packet->data.size()) memcpy(&send_packet[data_offset],packet->data.c_str(),packet->data.size());
    pcap_sendpacket(handle, reinterpret_cast<const u_char*>(send_packet),packet_length);
    free(send_packet);
    return;
}
void usage(void)
{
    printf("syntax : tcp-block <interface> <pattern>\n");
    printf("sample : tcp-block wlan0 \"Host: test.gilgil.net\"\n");
    return;
}
int main(int argc, char* argv[])
{
    if (argc!=3) {
        usage();
        return -1;
    }
    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1, errbuf);
    if (handle == nullptr) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    int ret=get_my_mac(dev);
    if(ret==FAIL) return -1;
    get_my_mac(dev);
    pattern_length=strlen(argv[2]);
    memcpy(pattern,argv[2],pattern_length);
    struct pcap_pkthdr* packet_hdr;
    const u_char* recv_packet;
    while(1) {
        ret=pcap_next_ex(handle, &packet_hdr, &recv_packet);
        if(ret==0) continue;
        if(ret<0) {
            printf("pcap_next_ex return %d error=%s\n",ret,pcap_geterr(handle));
            break;
        }
        ETH_HDR* packet_eth=(ETH_HDR*)recv_packet;
        if(ntohs(packet_eth->ether_type)!=ETHERTYPE_IP) continue;
        IP_HDR* packet_ip=(IP_HDR*)(recv_packet+sizeof(ETH_HDR));
        if(packet_ip->ip_p!=IPPROTO_TCP) continue;
        uint32_t ip_length=uint32_t(packet_ip->ip_hl)*4;
        TCP_HDR* packet_tcp=(TCP_HDR*)(recv_packet+ip_length+sizeof(ETH_HDR));
        uint32_t tcp_legnth=uint32_t(packet_tcp->th_off)*4;
        uint32_t header_len=ip_length+tcp_legnth;
        uint8_t* packet_data=(uint8_t*)(recv_packet+header_len+sizeof(ETH_HDR));
        uint32_t packet_length=(uint32_t)ntohs(packet_ip->ip_len)-header_len;
        if(strnstr(packet_data,pattern,packet_length)==NULL) continue;
        forward.data.clear();
        make_tcp_hdr(packet_tcp,packet_length);
        make_ip_hdr(packet_ip);
        make_eth_hdr(packet_eth);
        forward.tcp.th_sum=htons(tcp_checksum(&forward));
        backward.tcp.th_sum=htons(tcp_checksum(&backward));
        send_packet(handle,&forward);
        send_packet(handle,&backward);
    }
    pcap_close(handle);
    return 0;
}
