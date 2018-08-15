#include "parse.h"

parse::parse(int argc, char* argv[]){
    check_argc(argc);
    this->interface=argv[1];
}
void parse::check_argc(int argc){
    if(argc!=2){
        perror("< usage > : < interface > \n");
        exit(1);
    }
}
void parse::print_packet(uint8_t *packet, int length){
    for(int i=0; i<length; i++){
        if(i%16==0)
            cout << endl;
        printf("%02x ", packet[i]);
    }
    cout << endl;
}
