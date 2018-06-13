#include <QCoreApplication>
#include <iostream>
#include <pcap.h>
#include "parse.h"
#include "push_button.h"

using namespace std;
//vm이기때문에 eth0로 쏴야함 그럼 host에서 wifi3 즉 무선랜카드로 패킷이 나감
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
            case 0x41://error
            {
                cout << "GO" << endl;
                uint8_t b[52]={0x60, 0x60, 0x1f, 0xaa, 0x4b, 0x4d, 0x9c, 0xef, 0xd5, 0xfe, 0xc1, 0x51, 0x08, 0x00, 0x45, 0x00
                               , 0x00, 0x26, 0x07, 0xde, 0x40, 0x00, 0x80, 0x11, 0x5d, 0x94, 0xc0, 0xa8, 0x0a, 0x03, 0xc0, 0xa8
                               , 0x0a, 0x01, 0xff, 0x5c, 0x22, 0xb9, 0x00, 0x12, 0x76, 0xb5, 0x66, 0x6f, 0x72, 0x77, 0x61, 0x72
                               , 0x64, 0x20, 0x33, 0x30};
                 pcap_sendpacket(pcd,b,52); //temp
                 //pcap_sendpacket(pcd,ps.go,sizeof(ps.go));//<-why..error
                 pcap_sendpacket(pcd,ps.go_excute,sizeof(ps.go_excute));
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
