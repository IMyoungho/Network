#include "parse.h"
#include "convert_type.h"

parse::parse(int argc, char *argv[]){
    check_argc(argc, argv);
}
void parse::check_argc(int argc, char *argv[]){
    if(argc!=4)
    {
        cout << "***** 인자값이 잘못되었거나 존재하지 않습니다 *****\n";
        cout << "    >> 사용법 : <dev> <drone mac> <controller mac> \n";
        exit(1);
    }
    this->interface=argv[1];
    char_to_binary(argv[2],this->drone_mac);
    char_to_binary(argv[3],this->controller_mac);
}
char *parse::using_interface(){
    return this->interface;
}

uint8_t *parse::using_drone_mac(){
    return this->drone_mac;
}
uint8_t *parse::using_controller_mac(){
    return this->controller_mac;
}
