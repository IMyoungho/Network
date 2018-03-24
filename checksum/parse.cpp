#include "parse.h"

using namespace std;

parse::parse(int argc, char*argv[]){
    this->interface=argv[1];
    check_argc(argc);
}
void parse::check_argc(int argc){
    if(argc!=2){
        cout << "<usage> : <Interface>" << endl;
        exit(1);
    }
}
char* parse::using_interface(){
    return this->interface;
}
