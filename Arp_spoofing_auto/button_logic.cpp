#include "button_logic.h"

void button_logic(int button, map<keydata,valuedata>&data_map, parse *ps){
    cout << "<USAGE> :\n <R,r = Scanning> \n <M,m = Number of Session> \n <A,a = Select an argument> \n <N,n =  Clear> \n";
    map<keydata,valuedata>::iterator data_it;
//    int sequence=1;
//    char mac[18];
//    char ipbuf[15];
    while(true){
//        memset(ipbuf,0,15);
//        for(data_it = data_map.begin(); data_it!=data_map.end(); advance(data_it,1))
//        {
//             data_it->second.sequence=sequence;
//             printf("       %2d  ",data_it->second.sequence);
//             binary_to_char(mac,data_it);
//             cout << "    " << mac << "     ";
//             cout << inet_ntop(AF_INET,&data_it->second.ip,ipbuf,15) << endl;
//             sequence++;
//        }
        button = getch();
        switch (button) {
        case 82:
        case 114: //scanning network
        {
            cout << "R module" << endl;
            thread receive(receive_arp_packet,ps,data_map);
            make_arp_packet(ps);
            if(receive.joinable()==true)
                receive.join();
            else
                cout << "Error to Thread" << endl;
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
