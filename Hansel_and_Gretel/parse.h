#ifndef PARSE_H
#define PARSE_H
#include <iostream>
#include <convert_type.h>

using namespace std;

class parse{
private:
    char *interface;
    uint8_t drone_mac[6];
public:
    parse(int argc, char *argv[]);
    void check_argc(int argc, char*argv[]);
    char *using_interface();
    uint8_t *using_drone_mac();
    void show_load(int go, int back, int left, int right);
};

#endif // PARSE_H
