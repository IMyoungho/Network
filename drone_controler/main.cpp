#include <QCoreApplication>
#include <iostream>
#include <pcap.h>
#include "parse.h"
#include "push_button.h"

using namespace std;

int main(int argc, char *argv[])
{
    parse ps(argc,argv);
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
