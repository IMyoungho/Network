#include "char_to_binary.h"

void char_to_binary(char *str_mac, uint8_t arr_mac[6]){
    sscanf((const char*)str_mac, "%2hhX:%2hhX:%2hhX:%2hhX:%2hhX:%2hhX",&arr_mac[0],&arr_mac[1],&arr_mac[2],&arr_mac[3],&arr_mac[4],&arr_mac[5]);
}
