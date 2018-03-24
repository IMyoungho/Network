#include <iostream>
#include "parse.h"
#include "parse_packet.h"

using namespace std;

int main(int argc, char *argv[])
{
    cout << "Hello World!" << endl;
    parse ps(argc,argv);
    cal_checksum cc;
    parsing_in_packet(&ps, &cc);
    return 0;
}
