// bof.c
#include "beacon.h"  // ← Incluir la API

__attribute__((used))
__attribute__((visibility("default")))
void go(char *args, int alen) {
    BeaconPrintf(CALLBACK_OUTPUT, "[TEST BOF] Somehow, I'm still alive. Args=%.*s\n", alen, args);
    BeaconPrintf(CALLBACK_OUTPUT, "[TEST BOF] You're still alive!?. Args=%.*s\n", alen, args);
}
