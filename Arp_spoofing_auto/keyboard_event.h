#ifndef KEYBOARD_EVENT_H
#define KEYBOARD_EVENT_H
#include <stdio.h>
#include <termios.h>
#include <unistd.h>
#include <fcntl.h>

using namespace std;

int getch(void);
int kbhit(void);
#endif // KEYBOARD_EVENT_H
