#include "parse.h"

parse::parse(int argc, char*argv[]){
    this->interface = argv[1];
    memset(this->broadcast,0xff,6);
    check_argc(argc);
}

void parse::check_argc(int argc){
    if(argc!=2){
        cout << "< Usage > : < Interface >" << endl;
        exit(1);
    }
    this->parse_data_in_linux();
}

char * parse::using_interface(){
    return this->interface;
}

void parse::get_attacker_mac(uint8_t mac[6]){
    memcpy(this->attack_mac,mac,6);
}

void parse::get_attacker_ip(char ip[16]){
    inet_pton(AF_INET, ip, &this->attack_ip);
}
uint8_t *parse::using_attacker_mac(){
    return this->attack_mac;
}
uint32_t parse::using_attacker_ip(){
    return this->attack_ip;
}
uint8_t *parse::using_broadcast(){
    return this->broadcast;
}
void parse::parse_data_in_linux(){
    //-----------------------------get my(attacker) mac!!-----------------------------
    char host_mac[18];//mymac
    FILE *m;
    string str_ifconfig = "ifconfig ";
    string interface = this->interface;
    string regex = " | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}'";
    str_ifconfig=str_ifconfig+interface+regex;

    const char *command=str_ifconfig.c_str();
    m=popen(command,"r");
    fgets(static_cast<char*>(host_mac),18, m);
    uint8_t mac[6];
    char_to_binary(host_mac,mac);
    this->get_attacker_mac(mac);
    cout << " >> Your MAC = " << host_mac << endl;

    //-----------------------------get my(attacker) ip!!-----------------------------
    FILE *i;
    string base1 = "ip addr | grep '";
    string base2 = "' | grep brd | awk '{printf $2}' | awk -F/ ' {printf $1}'";
    base1+=interface+base2;
    const char* cmd = base1.c_str();
    i=popen(cmd,"r");
    char host_ip[15];
    fgets(host_ip,15,i);
    this->get_attacker_ip(host_ip);
    cout << " >> Your IP  = " << host_ip << endl;
    cout << "----------------------------------------------------" << endl;
}

void parse::make_arp_packet(){ //map을 인자로 make_arp_scanning? function name??
    uint8_t arp_packet[42];
    struct ether_header ep;
    struct arp_header ap;
    struct using_arp_type_data arp_assist;

    memcpy(ep.ether_shost,this->attack_mac,6);
    memcpy(ep.ether_dhost,this->broadcast,6);
    ep.ether_type=arp_assist.ether_arp_type;
    ap.hardware_type=arp_assist.hardware_type;
    ap.protocol_type=arp_assist.ipv4_type;
    ap.hardware_size=arp_assist.hardware_size;
    ap.protocol_size=arp_assist.protocol_size;
    ap.opcode=arp_assist.request_opcode;
    memcpy(ap.src_mac,this->attack_mac,6);
    memcpy(&ap.src_ip,&this->attack_ip,4);
    memcpy(ap.dst_mac,this->broadcast,6);
    memcpy(arp_packet,(uint8_t *)&ep,sizeof(ether_header));
    pcap_t *pcd;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcd=pcap_open_live(this->interface,BUFSIZ,1,1,errbuf);

    for(int i = 2; i< 255; i++)
    {
        memcpy(&ap.dst_ip, &this->attack_ip,4);//순차적으로 IP값이 하나씩 올라가면서 request를 진행하고 map에 넣는다
        uint8_t test[4]; //TEMP

        memcpy(arp_packet+sizeof(ether_header), (uint8_t*)&ap, sizeof(arp_header));
        pcap_sendpacket(pcd ,arp_packet, sizeof(arp_packet));
    }
    this->show_packet(arp_packet,42);
}
void parse::show_packet(uint8_t *packet, int length){
    for(int i=0; i<length; i++){
        if(i%16==0)
            cout << endl;
        printf("%02x ",packet[i]);
    }
    cout << endl;
}
void parse::choice_frame(){

}



