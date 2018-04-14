#include <QCoreApplication>
#include <pcap.h>
#include "parse.h"
#include "cal_checksum.h"
int main(int argc, char *argv[])
{
    parse ps(argc,argv);
    ps.parse_data_in_linux();
    cal_checksum cc;
    ps.parsing_in_packet(&cc);
    return 0;
}
