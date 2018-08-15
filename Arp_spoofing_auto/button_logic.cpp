#include "button_logic.h"

void button_logic(int button){
    cout << "<USAGE> :\n <R,r = Scanning> \n <M,m = Number of Session> \n <A,a = Select an argument> \n <N,n =  Clear> \n";
    while(true){
        button = getch();
        switch (button) {
        case 82:

        case 114: //scanning network
            cout << "R module" << endl;
        break;
        case 77:
        case 109: //choose how many session
            cout << "M module" << endl;
        break;
        case 65:
        case 97: // choose session
            cout << "A module" << endl;
        break;
        case 78:
        case 110: //clear
            cout << "N module" << endl;
            system("clear");
            cout << "<USAGE> :\n <R,r = Scanning> \n <M,m = Number of Session> \n <A,a = Select an argument> \n <N,n =  Clear> \n";
        break;
        default:
            cout << "[-]Wrong Button !!" << endl;
            break;
        }
    }
}
