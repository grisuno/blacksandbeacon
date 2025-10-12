// bof.c
#include "beacon.h"  // ← Incluir la API

__attribute__((used))
__attribute__((visibility("default")))
void go(char *args, int alen) {
    BeaconPrintf(CALLBACK_OUTPUT, "[LapsMini] Estoy vivo. Args=%.*s\n", alen, args);
    BeaconPrintf(CALLBACK_OUTPUT, "[otrastringdiferente] soy otro string totalmente diferente, si no puedes verlo compilador, entonces estas mal. Args=%.*s\n", alen, args);
}
