#ifndef CONVERT_TYPE_H
#define CONVERT_TYPE_H
#include <stdint.h>
#include <cstdio>
#include <map>
#include "setting_map.h"

using namespace std;

void char_to_binary(char *str_mac, uint8_t arr_mac[6]);
void binary_to_char(char str_mac[18], map<keydata, valuedata>::iterator data_it);
#endif // CONVERT_TYPE_H
