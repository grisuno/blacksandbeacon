// beacon_api.h
#ifndef BEACON_API_H
#define BEACON_API_H

#include <stdint.h>
#include <stdarg.h>

// Tipos de callback
#define CALLBACK_OUTPUT 0x00
#define CALLBACK_ERROR  0x0D
#define CALLBACK_OUTPUT_OEM 0x0E

// Estructura para parsing de datos (opcional, para comandos complejos)
typedef struct {
    char *original;
    char *buffer;
    int   length;
} datap;

// === API para BOFs ===
void BeaconDataParse(datap *parser, char *buffer, int size);
char *BeaconDataPtr(datap *parser, int size);
int BeaconDataInt(datap *parser);
short BeaconDataShort(datap *parser);
int BeaconDataLength(datap *parser);
char *BeaconDataExtract(datap *parser, int *size);
void BeaconPrintf(int type, const char *fmt, ...);
void BeaconOutput(int type, const char *data, int len);

#endif // BEACON_API_H
