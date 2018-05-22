#include <QCoreApplication>
#include <iostream>
#include <pcap.h>
#include <string.h>
#include <parse.h>
#include <thread>
#include "keyboard_event.h"
#include "hopping_channel.h"

using namespace std;

int main(int argc, char *argv[])
{
    cout << "____________________________________Fake AP____________________________________\n";
    parse ps(argc,argv);
    map<keydata, valuedata> map_beacon;
    while(true){
        int num=getch();
        switch (num) {
        case 82:
        case 114:
        {
      //    thread hopping_2G(auto_change_2ghz,ps.using_interface(),30); //atomic and second add!!
      //    if(hopping_2G.joinable()==true)
      //        hopping_2G.join();
      //    else
      //        cout << " >> Error to join thread!!\n";
            ps.scanning(map_beacon);
        }
        break;
        case 87:
        case 119:
        {

        }
        break;
        case 78: //N
        case 110://n
            system("clear");
        break;
        default:
            break;
        }
    }
    return 0;
}
