#include "parse_data_in_linux.h"

void parse_data_in_linux(parse_data *parse){
    //-----------------------------get my(attacker) mac!!-----------------------------
    char host_mac[18];//mymac
    FILE *m;
    string str_ifconfig = "ifconfig ";
    string interface = parse->using_interface();
    string regex = " | grep -o -E '([[:xdigit:]]{1,2}:){5}[[:xdigit:]]{1,2}'";
    str_ifconfig=str_ifconfig+interface+regex;

    const char *command=str_ifconfig.c_str();
    m=popen(command,"r");
    fgets((char*)host_mac,18, m);
    uint8_t mac[6];
    char_to_binary(host_mac,mac);
    parse->get_attacker_mac(mac);

    //-----------------------------get my(attacker) ip!!-----------------------------
    FILE *i;
    string base1 = "ip addr | grep '";
    string base2 = "' | grep brd | awk '{printf $2}' | awk -F/ ' {printf $1}'";
    base1+=interface+base2;
    const char* cmd = base1.c_str();
    i=popen(cmd,"r");
    char host_ip[15];
    fgets(host_ip,15,i);
    parse->get_attacker_ip(host_ip);
}
