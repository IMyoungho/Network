#ifndef PARSE_H
#define PARSE_H
#include <iostream>

using namespace std;


class parse{
private:
    char *interface;
    uint8_t drone_mac[6];
    uint8_t controller_mac[6];
public:
    parse(int argc, char *argv[]);
    void check_argc(int argc, char *argv[]);
    char *using_interface();
    uint8_t *using_drone_mac();
    uint8_t *using_controller_mac();

};

#endif // PARSE_H
