#include <QCoreApplication>
#include <iostream>
#include <pcap.h>
#include "parse.h"
#include "push_button.h"

using namespace std;
//vm이기때문에 eth0로 쏴야함 그럼 host에서 wifi3 즉 무선랜카드로 패킷이 나감
//host로 drone에 연결하고 ip 확인 후 my ip인자값으로 준다. guest는 유선으로 연결
//mac주소는 vm을 거치면서 자동으로 변환됨으로 신경은 일단쓰지말자 하지만 쏘는 ip는 정확히 맞춰줘야함
int main(int argc, char *argv[])
{
    parse ps(argc,argv);
    cal_checksum cc;
    ps.make_common_packet(&cc);
    pcap_t *pcd;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcd=pcap_open_live(ps.using_interface(), BUFSIZ, 1, 1, errbuf);
    pcap_sendpacket(pcd,ps.command,sizeof(ps.command));
    while(true){
        int num=getch();
        switch (num) {
            case 0x31://1
            {
                cout << "Take Off" << endl;
                pcap_sendpacket(pcd,ps.takeoff,sizeof(ps.takeoff));
            }
            break;
            case 0x32://2
            {
                cout << "Landing" << endl;
                pcap_sendpacket(pcd,ps.landing,sizeof(ps.landing));
            }
            break;
            case 0x51://Q
            case 0x71://q
            {
                cout << "UP" << endl;
                pcap_sendpacket(pcd,ps.up,sizeof(ps.up));
                pcap_sendpacket(pcd,ps.up_excute,sizeof(ps.up_excute));
            }
            break;
            case 0x57://W
            case 0x77://w
            {
                cout << "DOWN" << endl;
                pcap_sendpacket(pcd,ps.down,sizeof(ps.down));
                pcap_sendpacket(pcd,ps.down_excute,sizeof(ps.down_excute));
            }
            break;
            case 0x41:
            {
                cout << "Forward" << endl;
                 pcap_sendpacket(pcd,ps.forward,sizeof(ps.forward));
                 pcap_sendpacket(pcd,ps.forward_excute,sizeof(ps.forward_excute));
            }
            break;
            case 0x42:
            {
                cout << "BACK" << endl;
                pcap_sendpacket(pcd,ps.back,sizeof(ps.back));
                pcap_sendpacket(pcd,ps.back_excute,sizeof(ps.back_excute));
            }
            break;
            case 0x43:
            {
                cout << "RIGHT" << endl;
                pcap_sendpacket(pcd,ps.right,sizeof(ps.right));
                pcap_sendpacket(pcd,ps.right_excute,sizeof(ps.right_excute));
            }
            break;
            case 0x44:
            {
                cout << "LEFT" << endl;
                pcap_sendpacket(pcd,ps.left,sizeof(ps.left));
                pcap_sendpacket(pcd,ps.left_excute,sizeof(ps.left_excute));
            }
            break;
        }
    }
    return 0;
}
