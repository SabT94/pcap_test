#include <pcap.h>
#include <stdio.h>
#include <stdint.h>
void usage() {
  printf("syntax: pcap_test <interface>\n");
  printf("sample: pcap_test wlan0\n");
}
typedef struct mac{
    uint8_t D_Mac[6];
    uint8_t S_Mac[6];
    uint16_t Type;
}mac;
typedef struct ip{
    uint8_t VerANDIhl;//verANDIhl &FFFF0000 = version || &0000FFFF = header length
    uint8_t TOS; // type of service
    uint16_t TPL;//Total Packet Length
    uint16_t Identify;
    uint16_t FFlagANDFOffset;
    uint8_t TTL;
    uint8_t ProtocolID;
    uint16_t CheckSum;
    uint8_t SIPAddr[4];
    uint8_t DIPAddr[4];
}ip;
typedef struct tcp{
    uint8_t Sport[2];
    uint8_t Dport[2];
    uint32_t SeqNum;
    uint32_t AcknowNum;
    uint8_t DataRe;//data offset(4bits) + reserved(3bits) + control flags(1bits)
    uint8_t ControlF;// control flags(8bits)
    uint16_t WSize;
    uint16_t CheckSum;
    uint16_t UrgentPointer;
}tcp;
typedef struct Tcp_Data{
    uint8_t Text[10];
}Tcp_Data;
uint16_t my_ntohs(uint16_t n) {
    return n >> 8 | n << 8;
}
void print_mac(u_int8_t *mac_A){
    for(int i=0;i<6;i++){
    printf("%02x",mac_A[i]);
    if(i!=5)
        putchar(':');
    }
    putchar('\n');
}
void print_ip(uint8_t *ip_A){
    for(int i=0;i<4;i++){
        printf("%d",ip_A[i]);
        if(i!=3){
            putchar('.');
        }
    }
    putchar('\n');
}
void print_port(uint8_t *port){
    printf("%d",port[0]<<8 | port[1]);
    putchar('\n');
}
void print_data(uint8_t *data,uint16_t total_length,uint8_t ip_header_length,uint8_t tcp_header_length){
    total_length = (total_length<<8|total_length>>8);
    //total_length = (total_length<<8|total_length>>8) - (ip_header_length-tcp_header_length);
    total_length -= (ip_header_length+tcp_header_length);
    printf("TCP DATA LENGTH = %d\n",total_length);
    if(total_length != 0){
        for(int i=0; i<10;i++){
            printf(" %02x ",data[i]);
            if(i!=9){
                putchar(':');
            }
        }
        putchar('\n');
    }
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
    struct mac * mac_address;
    struct ip *ip_info;
    struct tcp *tcp_info;
    struct Tcp_Data *data;
    int res = pcap_next_ex(handle, &header, &packet);
    if (res == 0) continue;
    if (res == -1 || res == -2) break;
    mac_address = (mac*)packet;
    printf("DES_Mac : ");
    print_mac(mac_address->D_Mac);
    printf("SOU_Mac : ");
    print_mac(mac_address->S_Mac);
    if(my_ntohs(mac_address->Type)==0x0800){
        ip_info = (ip*)(packet+ sizeof(struct mac));
        printf("SIP : ");
        print_ip(ip_info->SIPAddr);
        printf("DIP : ");
        print_ip(ip_info->DIPAddr);
        uint8_t ip_length = (ip_info->VerANDIhl&0x0f)*4;
        if(ip_info->ProtocolID==0x06){
            tcp_info = (tcp*)(packet + (ip_length+sizeof(struct mac)));
            printf("SPort : ");
            print_port(tcp_info->Sport);
            printf("DPort : ");
            print_port(tcp_info->Dport);
            uint8_t tcp_length = ((tcp_info->DataRe>>4)*4);
            data = (Tcp_Data*)(packet + (ip_length)+sizeof(struct mac)+tcp_length);
            print_data(data->Text,ip_info->TPL,ip_length,tcp_length);
        }
    }
    printf("-----------------------------------------\n");

}
  pcap_close(handle);
  return 0;
}
