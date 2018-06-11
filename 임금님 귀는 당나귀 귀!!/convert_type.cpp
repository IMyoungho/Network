#include "convert_type.h"

void convert_type(char *str, uint8_t mac[6], int type){
    switch (type) {
    case 0: sprintf(str,"%02X:%02X:%02X:%02X:%02X:%02X", mac[0],mac[1],mac[2],mac[3],mac[4],mac[5]);
    break;
    case 1: sscanf((const char*)str, "%2hhX:%2hhX:%2hhX:%2hhX:%2hhX:%2hhX",&mac[0],&mac[1],&mac[2],&mac[3],&mac[4],&mac[5]);
    break;
    default: cout << "< 0 : binary to char >  < 1 : char to binary >\n";
    break;
    }
}
