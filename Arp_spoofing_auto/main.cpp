#include <iostream>
#include "button_logic.h"
#include "parse.h"

using namespace std;

int main(int argc, char* argv[])
{
    parse ps(argc,argv);
    int button=0;
    button_logic(button);

    return 0;
}
