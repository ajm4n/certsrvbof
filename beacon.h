#ifndef _H_BEACON
#define _H_BEACON

#include <windows.h>

typedef struct {
	char * original;
	char * current;
	int   length;
} datap;

typedef struct {
	char * buffer;
	int length;
	int capacity;
} formatp;

DECLSPEC_IMPORT void    BeaconDataParse(datap * parser, char * buffer, int size);
DECLSPEC_IMPORT char *  BeaconDataExtract(datap * parser, int * size);
DECLSPEC_IMPORT int     BeaconDataInt(datap * parser);
DECLSPEC_IMPORT short   BeaconDataShort(datap * parser);

DECLSPEC_IMPORT void    BeaconFormatAlloc(formatp * format, int max);
DECLSPEC_IMPORT void    BeaconFormatReset(formatp * format);
DECLSPEC_IMPORT void    BeaconFormatFree(formatp * format);
DECLSPEC_IMPORT void    BeaconFormatAppend(formatp * format, char * text, int len);
DECLSPEC_IMPORT void    BeaconFormatPrintf(formatp * format, char * fmt, ...);
DECLSPEC_IMPORT char *  BeaconFormatToString(formatp * format, int * size);

DECLSPEC_IMPORT void    BeaconPrintf(int type, char * fmt, ...);
DECLSPEC_IMPORT void    BeaconOutput(int type, char * data, int len);
DECLSPEC_IMPORT void    BeaconError(char * fmt, ...);

#define CALLBACK_OUTPUT 0x0
#define CALLBACK_ERROR  0x1
#define CALLBACK_OUTPUT_OEM 0x2
#define CALLBACK_ERROR_OEM  0x3
#define CALLBACK_FILE    0x20

#endif

