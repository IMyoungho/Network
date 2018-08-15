#include "convert_type.h"

void char_to_binary(char *str_mac, uint8_t arr_mac[6]){
    sscanf(static_cast<const char*>(str_mac), "%2hhX:%2hhX:%2hhX:%2hhX:%2hhX:%2hhX",&arr_mac[0],&arr_mac[1],&arr_mac[2],&arr_mac[3],&arr_mac[4],&arr_mac[5]);
}
//void binary_to_char(char str_mac[18], map<keydata, valuedata>::iterator data_it){
//    sprintf(str_mac,"%02X:%02X:%02X:%02X:%02X:%02X",data_it->first.mac[0],data_it->first.mac[1],data_it->first.mac[2],data_it->first.mac[3],data_it->first.mac[4],data_it->first.mac[5]);
//}
