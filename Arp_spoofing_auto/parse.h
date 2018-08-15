#ifndef PARSE_H
#define PARSE_H
#include <iostream>

using namespace std;

class parse{
private:
    char *interface;
public:
    parse(int argc, char* argv[]);
    void check_argc(int argc);
    void print_packet(uint8_t *packet, int length);
};

#endif // PARSE_H
