#ifndef CONVER_CHAR_TO_BINARY_H
#define CONVER_CHAR_TO_BINARY_H

void char_to_binary(char *str_mac, uint8_t *mac){
    sscanf((const char*)str_mac, "%2hhX:%2hhX:%2hhX:%2hhX:%2hhX:%2hhX",&mac[0],&mac[1],&mac[2],&mac[3],&mac[4],&mac[5]);
}
#endif // CONVER_CHAR_TO_BINARY_H
