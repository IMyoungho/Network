#include <QCoreApplication>
#include <iostream>
#include <pcap.h>
#include "parse.h"
#include "push_button.h"

using namespace std;
//vm이기때문에 eth0로 쏴야함 그럼 host에서 wifi3 즉 무선랜카드로 패킷이 나감
int main(int argc, char *argv[])
{
    parse ps(argc,argv);
    ps.make_packet();
    while(true){
        int num=getch();
        switch (num) {
        case 0x31:
            cout << "Take Off" << endl;
        break;
        case 0x32:
            cout << "Landing" << endl;
        break;
        case 0x51:
        case 0x71:
            cout << "UP" << endl;
        break;
        case 0x57:
        case 0x77:
            cout << "DOWN" << endl;
        break;
        case 0x41:
            cout << "GO" << endl;
        break;
        case 0x42:
            cout << "BACK" << endl;
        break;
        case 0x43:
            cout << "RIGHT" << endl;
        break;
        case 0x44:
            cout << "LEFT" << endl;
        break;
        }
    }
    return 0;
}
