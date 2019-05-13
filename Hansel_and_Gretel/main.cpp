#include <iostream>
#include <pcap.h>
#include "parse.h"
#include "come_packet.h"

#define PROMISCUOUS 1
#define NONPROMISCUOUS 0

using namespace std;

int main(int argc, char *argv[])
{
    cout <<"**************** Hansel and Gretel ****************" << endl;
    cout <<"   Copyright 2019. IMyoungho. All rights reseved" << endl;
    cout <<"***************************************************\n" << endl;
    parse ps(argc, argv);
    come_packet(&ps);
    return 0;
}
