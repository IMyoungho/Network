#ifndef HOPPING_CHANNEL_H
#define HOPPING_CHANNEL_H
#include <string>
#include <unistd.h>
#include <atomic>

using namespace std;

void auto_change_2ghz(char *interface, int seconds);
void auto_change_5ghz(char *interface, int seconds);
#endif // HOPPING_CHANNEL_H
