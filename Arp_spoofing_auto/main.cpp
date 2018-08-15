#include <iostream>
#include <map>
#include "button_logic.h"
#include "parse.h"
#include "setting_map.h"

using namespace std;

int main(int argc, char* argv[])
{
    parse ps(argc,argv);
    int button=0;
    map<keydata,valuedata>data_map;
    button_logic(button,data_map,&ps);

    return 0;
}

