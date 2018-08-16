#include "button_logic.h"

void button_logic(int button, map<keydata,valuedata>&data_map, parse *ps){
    cout << "<USAGE> :\n <R,r = Scanning> \n <M,m = Number of Session> \n <A,a = Select an argument> \n <N,n =  Clear> \n";
    char errbuf[PCAP_ERRBUF_SIZE];
    while(true){
        button = getch();
        switch (button) {
        case 82:
        case 114: //scanning network
        {
            cout << "R module" << endl;
            thread tt(receive_arp_packet,ps);
            make_arp_packet(ps);
            tt.join();
        }
        break;
        case 77:
        case 109: //choose how many session
        {

            cout << "M module" << endl;
        }
        break;
        case 65:
        case 97: // choose session
        {
            cout << "A module" << endl;
        }
        break;
        case 78:
        case 110: //clear
        {
            cout << "N module" << endl;
            system("clear");
            cout << "<USAGE> :\n <R,r = Scanning> \n <M,m = Number of Session> \n <A,a = Select an argument> \n <N,n =  Clear> \n";
       }
        break;
        default:
            cout << "[-]Wrong Button !!" << endl;
            break;
        }
    }
}
