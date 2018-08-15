#ifndef BUTTON_LOGIC_H
#define BUTTON_LOGIC_H
#include <iostream>
#include <stdlib.h>
#include <atomic>
#include "keyboard_event.h"
#include "setting_map.h"
#include "module_r.h"
#include "module_a.h"

using namespace std;

void button_logic(int button, map<keydata, valuedata> &data_map, parse *ps);
#endif // BUTTON_LOGIC_H
