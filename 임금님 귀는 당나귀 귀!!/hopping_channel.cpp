#include "hopping_channel.h"
string base="iwconfig ";
string base2 =" channel ";
void auto_change_2ghz(char *interface, atomic<bool> &run){
int i = 1, j = 1;
    string excute_code,num;
    char *basecode;
    while(run)
    {
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
void auto_change_5ghz(char *interface, atomic<bool>&run)
{
    int i = 36;
    string excute_code,num;
    char * basecode;

    while(run)
    {
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
