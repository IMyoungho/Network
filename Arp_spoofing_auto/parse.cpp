#include "parse.h"

parse::parse(int argc, char* argv[]){
    this->interface=argv[1];
    this->check_argc(argc);
    memset(this->broadcast,0xff,6);
}

void parse::check_argc(int argc){
    if(argc!=2){
        perror("< usage > : < interface > \n");
        exit(1);
    }
    parse_data_in_linux();
}

void parse::print_packet(uint8_t *packet, int length){
    for(int i=0; i<length; i++){
        if(i%16==0)
            cout << endl;
        printf("%02x ", packet[i]);
    }
    cout << endl;
}
char* parse::using_interface(){
    return this->interface;
}
void parse::get_attacker_mac(uint8_t mac[6]){
    memcpy(this->attacker_mac,mac,6);
}
void parse::get_attacker_ip(char ip[16]){
    inet_pton(AF_INET, ip, &this->attacker_ip);
}
uint8_t *parse::using_attacker_mac(){
    return this->attacker_mac;
}
uint32_t parse::using_attacker_ip(){
    return this->attacker_ip;
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
void parse::show_packet(uint8_t *packet, int length){
    for(int i=0; i < length; i++){
        if(i%16==0)
            cout << endl;
        printf("%02x ",packet[i]);
    }
    cout << endl;
}


void parse::get_start_time(clock_t start){
    this->start_time=start;
}
void parse::get_end_time(clock_t end){
    this->end_time=end;
}

clock_t parse::using_start_time(){
    return this->start_time;
}
clock_t parse::using_end_time(){
    return this->end_time;
}

