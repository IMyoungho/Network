#include "hopping_channel.h"
void auto_change_2ghz(char *interface, int seconds)
{
    int i = 1, j = 1;
    string base="iwconfig ";
    string base2 =" channel ";
    string excute_code,num;
    char *basecode;
    time_t start_time{0},end_time{0};
    time(&start_time);
    while(end_time-start_time<=seconds)
    {
        time(&end_time);
        if(i>14)
        {
            if(j==13)
                j=0;
            i=1+j;
            j++;
        }
        num=to_string(i);
        excute_code=base+interface+base2+num;
        basecode=(char*)excute_code.c_str();
        system(basecode);
        sleep(1);
        i+=6;
    }
}
void auto_change_5ghz(char *interface, int seconds)
{
    int i = 36;
    string base="iwconfig ";
    string base2 =" channel ";
    string excute_code,num;
    char * basecode;
    time_t start_time{0},end_time{0};
    time(&start_time);
    while(end_time-start_time<=seconds)
    {
        time(&end_time);
        switch (i)
        {
            case 68:
                i=100;
            break;
            case 128:
                i=149;
            break;
            case 165:
                i=36;
            break;
            default:
            break;
        }
        num=to_string(i);
        excute_code=base+interface+base2+num;
        basecode=(char*)excute_code.c_str();
        system(basecode);
        sleep(1);
        i+=4;
    }
}
