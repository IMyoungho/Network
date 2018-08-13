#include <iostream>
#include <map>
#include "parse.h"


using namespace std;

int main(int argc, char *argv[])
{
    cout << "!! Hello ARP Spoofing !!" << endl;
    parse ps(argc, argv);
    ps.make_arp_packet();
    cout<< "bye" << endl;
    return 0;
}
