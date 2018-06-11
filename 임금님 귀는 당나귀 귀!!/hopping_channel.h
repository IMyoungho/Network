#ifndef HOPPING_CHANNEL_H
#define HOPPING_CHANNEL_H
#include <string>
#include <unistd.h>
#include <atomic>

using namespace std;

void auto_change_2ghz(char *interface, atomic<bool> &run);
void auto_change_5ghz(char *interface, atomic<bool> &run);
#endif // HOPPING_CHANNEL_H
