#include <QCoreApplication>
#include <iostream>
#include <pcap.h>
#include <string.h>
#include <parse.h>
#include <thread>
#include "keyboard_event.h"
#include "hopping_channel.h"
#include "convert_type.h"

using namespace std;

int main(int argc, char *argv[])
{
    cout << "____________________________________Fake AP____________________________________\n";
    parse ps(argc,argv);
    map<keydata, valuedata> map_beacon;
    //map<keydata, valuedata>::iterator bea_it;
    while(true){
        int num=getch();
        switch (num) {
        case 82:
        case 114:
        {
            atomic<bool>run{true};
            thread hopping_2G(auto_change_2ghz,ps.using_interface(),ref(run)); //atomic and second add!!
            ps.scanning(map_beacon,ref(run));
            if(hopping_2G.joinable()==true)
                hopping_2G.join();
            else
                cout << " >> Error to join thread!!\n";
        }
        break;
        getchar();
        case 87:
        case 119:
        {

        }
        break;
        getchar();
        case 78:
        case 110:
        break;
        getchar();
        }
        getchar();
        ps.show_ap(map_beacon);
    }
    return 0;
}
