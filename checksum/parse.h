#ifndef PARSE_H
#define PARSE_H
#include <iostream>
#include <stdint.h>
#include <string.h>
#include <netinet/ether.h>
#include <netinet/ip.h>
#include <arpa/inet.h>

using namespace std;

class parse {
private:
    char *interface;
public:
    parse(int argc, char *argv[]);
    void check_argc(int argc);
    char* using_interface();
};
#endif // PARSE_H
