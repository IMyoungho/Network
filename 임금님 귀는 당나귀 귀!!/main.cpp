#include <QCoreApplication>
#include <iostream>
#include <pcap.h>
#include <string.h>
#include <thread>
#include "parse.h"
#include "keyboard_event.h"
#include "hopping_channel.h"
#include "convert_type.h"

using namespace std;

int main(int argc, char *argv[])
{
    cout << "______________________________임금님 귀는 당나귀 귀!!___________________________\n";
    cout << "\t\t\tCopyrightⓒ 2018.05.29 By IMYoungho \n";
    cout << "\n\n\t\t\t | Press Your 'R' or 'r' KEY |\n";
    parse ps(argc,argv);
    map<keydata, valuedata> map_beacon;
    while(true){
        int num=getch();
        switch (num) {
            case 82:
            case 114:
            {
                atomic<bool>run{true};
                thread hopping_2G(auto_change_2ghz,ps.using_interface(),ref(run));
                ps.scanning(map_beacon,ref(run));
                if(hopping_2G.joinable()==true)
                    hopping_2G.join();
                else
                    cout << " >> Error to join thread!!\n";
                getchar();
            }
            break;
            case 87:
            case 119:
            {
                ps.ask_ap();
                ps.select_ap(map_beacon);
                getchar();
            }
            break;

            case 78:
            case 110:
            {
                system("clear");
                ps.show_ap(map_beacon);
                getchar();
            }
            break;
            default:
            break;
        }
        ps.show_ap(map_beacon);
    }
    return 0;
}
