#include "parse.h"


parse::parse(int argc, char *argv[]){
    check_argc(argc, argv);
}
void parse::check_argc(int argc, char *argv[]){
    if(argc!=3){
        cout << "***** 인자값이 잘못되었거나 존재하지 않습니다 *****\n";
        cout << "      < Usage > : < interface > < Drone Mac >\n" << endl;
        exit(0);
    }
    this->interface=argv[1];
    char_to_binary(argv[2],this->drone_mac);
}
char *parse::using_interface(){
    return this->interface;
}
uint8_t *parse::using_drone_mac(){
    return this->drone_mac;
}
void parse::show_load(int go, int back, int left, int right){

}
