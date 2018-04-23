#include "convert_char_to_binary.h"

void char_to_binary(char *str_mac, uint8_t *mac){
    sscanf((const char*)str_mac, "%2hhX:%2hhX:%2hhX:%2hhX:%2hhX:%2hhX",&mac[0],&mac[1],&mac[2],&mac[3],&mac[4],&mac[5]);
}
