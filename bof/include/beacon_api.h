/*
 * beacon_api.h - Shared BOF API for Black Sand Beacon
 *
 * Include this in every BOF. It declares the symbols the beacon
 * exports and gives the BOF a clean way to call back into the
 * beacon for output.
 *
 * BOFs MUST export a function with this exact signature:
 *
 *     void go(char *args, int alen);
 *
 * The args/alen pair is raw bytes the operator passes when
 * scheduling the BOF (use BeaconDataParse / BeaconDataInt / etc.
 * to pull fields out of it).
 */
#ifndef BSB_BOF_BEACON_API_H
#define BSB_BOF_BEACON_API_H

#include <stdint.h>
#include <stddef.h>
#include <stdarg.h>

/* Callback types. Kept compatible with the original beacon.h. */
#define CALLBACK_OUTPUT      0x00
#define CALLBACK_ERROR       0x0D
#define CALLBACK_OUTPUT_OEM  0x0E

/* Argument parser. BOFs that want to read structured args fill
 * one of these in via BeaconDataParse then pull fields out. */
typedef struct {
    char *original;
    char *buffer;
    int   length;
} datap;

void BeaconDataParse(datap *parser, char *buffer, int size);
char *BeaconDataPtr(datap *parser, int size);
int   BeaconDataInt(datap *parser);
short BeaconDataShort(datap *parser);
int   BeaconDataLength(datap *parser);
char *BeaconDataExtract(datap *parser, int *size);

/* Output callbacks. BeaconPrintf works like printf, BeaconOutput
 * takes a raw byte buffer (len may be 0 for strlen-style strings
 * but the buffer must still be NUL-terminated). */
void BeaconPrintf(int type, const char *fmt, ...);
void BeaconOutput(int type, const char *data, int len);

#endif /* BSB_BOF_BEACON_API_H */
