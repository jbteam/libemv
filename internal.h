#ifndef __INTERNAL_H
#define __INTERNAL_H

#include <stddef.h>

// Apdu transmit
extern char (*libemv_ext_apdu)(unsigned char cla, unsigned char ins, unsigned char p1, unsigned char p2,
						  unsigned char dataSize, const unsigned char* data,
						  int* outDataSize, unsigned char* outData);

// Alloc
extern void* (*libemv_malloc)(size_t size);
extern void* (*libemv_realloc)(void* ptr, size_t size);
extern void (*libemv_free)(void * ptr);

// Date time
extern void (*libemv_get_date)(char* strdate);
extern void (*libemv_get_time)(char* strtime);

// Random
extern int (*libemv_rand)(void);

// Debug
extern int (*libemv_printf)(const char * format, ...);

// Debug disabled / enabled
extern char libemv_debug_enabled;

// Debug out binary
void libemv_debug_buffer(char* strPre, unsigned char* buf, int size, char* strPost);

// Init and destroy application buffer
void libemv_init_tlv_buffer(void);
void libemv_destroy_tlv_buffer(void);

// Add or update tag in application buffer
void libemv_set_tag(unsigned short tag, unsigned char* data, int size);

// Clear application buffer data (not free memory)
void libemv_clear_tlv_buffer(void);

// Parse custom tlv buffer
// outBuffer will point to inBuffer with some shift
// Returns shift to the end of current [tag length value]
int libemv_parse_tlv(unsigned char* inBuffer, int inBufferSize, unsigned short* outTag, unsigned char** outBuffer, int* outSize);

// Make tlv from data (1 tag)
// Returns maked size of tlvBuffer
int libemv_make_tlv(unsigned char* inBuffer, int inBufferSize, unsigned short tag, unsigned char* tlvBuffer);

// Make data from DOL list. If no data in buffer - fill zeros
// Returns size of outBuffer
int libemv_dol(unsigned char* dol, int dolSize, unsigned char* outBuffer);

// Settings
extern LIBEMV_SETTINGS libemv_settings;
extern LIBEMV_GLOBAL libemv_global;
extern int libemv_applications_count;
extern LIBEMV_APPLICATIONS* libemv_applications;
void libemv_destroy_settings(void);

// Apdu function with debug info
char libemv_apdu(unsigned char cla, unsigned char ins, unsigned char p1, unsigned char p2,
				 unsigned char dataSize, const unsigned char* data,
				 int* outDataSize, unsigned char* outData);

// Tags
#define TAG_FCI_TEMPLATE					0x6F
#define TAG_DF_NAME							0x84
#define TAG_FCI_PROP_TEMPLATE				0xA5
#define TAG_SFI_OF_DEF						0x88
#define TAG_LANGUAGE_PREFERENCE				0x5F2D
#define TAG_ISSUER_CODE_TABLE_INDEX			0x9F11
#define TAG_FCI_ISSUER_DISCR_DATA			0xBF0C
#define TAG_APPLICATION_LABEL				0x50
#define TAG_APP_PRIORITY_INDICATOR			0x87
#define TAG_PDOL							0x9F38
#define TAG_TVR								0x95
#define TAG_TSI								0x9B
#define TAG_APPLICATION_TEMPLATE			0x61
#define TAG_ADF_NAME						0x4F
#define TAG_APP_PREFERRED_NAME				0x9F12
#define TAG_TERMINAL_CAPABILITIES			0x9F33
#define TAG_ADDI_TERMINAL_CAPABILITIES		0x9F40
#define TAG_AID								0x9F06
#define TAG_IFD_SERIAL_NUMBER				0x9F1E
#define TAG_TERMINAL_COUNTRY_CODE			0x9F1A
#define TAG_TERMINAL_TYPE					0x9F35
#define TAG_ACQUIRER_ID						0x9F01
#define TAG_APPLICATION_VERSION_NUMBER		0x9F08
#define TAG_MCC								0x9F15
#define TAG_MERCHANT_ID						0x9F16
#define TAG_MERCHANT_NAME_AND_LOCATION		0x9F4E
#define TAG_TERMINAL_FLOOR_LIMIT			0x9F1B
#define TAG_TERMINAL_ID						0x9F1C
#define TAG_RISK_MANAGEMENT_DATA			0x9F1D
#define TAG_TRANSACTION_REFERENCE_CURRENCY	0x9F3C
#define TAG_TRANSACTION_REFERENCE_EXPONENT	0x9F3D
#define TAG_AIP								0x82
#define TAG_AFL								0x94
#define TAG_COMMAND_TEMPLATE				0x83
#define TAG_RESPONSE_FORMAT_1				0x80
#define TAG_RESPONSE_FORMAT_2				0x77
#define TAG_READ_RECORD_RESPONSE_TEMPLATE	0x70
#define TAG_APPLICATION_EXP_DATE			0x5F24
#define TAG_PAN								0x5A
#define TAG_CDOL_1							0x8C
#define TAG_CDOL_2							0x8D

// Bit map, please control out of limits
typedef struct
{
#ifdef BIG_ENDIAN
	unsigned char B1b8:1;
	unsigned char B1b7:1;
	unsigned char B1b6:1;
	unsigned char B1b5:1;
	unsigned char B1b4:1;
	unsigned char B1b3:1;
	unsigned char B1b2:1;
	unsigned char B1b1:1;

	unsigned char B2b8:1;
	unsigned char B2b7:1;
	unsigned char B2b6:1;
	unsigned char B2b5:1;
	unsigned char B2b4:1;
	unsigned char B2b3:1;
	unsigned char B2b2:1;
	unsigned char B2b1:1;

	unsigned char B3b8:1;
	unsigned char B3b7:1;
	unsigned char B3b6:1;
	unsigned char B3b5:1;
	unsigned char B3b4:1;
	unsigned char B3b3:1;
	unsigned char B3b2:1;
	unsigned char B3b1:1;

	unsigned char B4b8:1;
	unsigned char B4b7:1;
	unsigned char B4b6:1;
	unsigned char B4b5:1;
	unsigned char B4b4:1;
	unsigned char B4b3:1;
	unsigned char B4b2:1;
	unsigned char B4b1:1;

	unsigned char B5b8:1;
	unsigned char B5b7:1;
	unsigned char B5b6:1;
	unsigned char B5b5:1;
	unsigned char B5b4:1;
	unsigned char B5b3:1;
	unsigned char B5b2:1;
	unsigned char B5b1:1;
#else
	unsigned char B1b1:1;
	unsigned char B1b2:1;
	unsigned char B1b3:1;
	unsigned char B1b4:1;
	unsigned char B1b5:1;
	unsigned char B1b6:1;
	unsigned char B1b7:1;
	unsigned char B1b8:1;

	unsigned char B2b1:1;
	unsigned char B2b2:1;
	unsigned char B2b3:1;
	unsigned char B2b4:1;
	unsigned char B2b5:1;
	unsigned char B2b6:1;
	unsigned char B2b7:1;
	unsigned char B2b8:1;

	unsigned char B3b1:1;
	unsigned char B3b2:1;
	unsigned char B3b3:1;
	unsigned char B3b4:1;
	unsigned char B3b5:1;
	unsigned char B3b6:1;
	unsigned char B3b7:1;
	unsigned char B3b8:1;

	unsigned char B4b1:1;
	unsigned char B4b2:1;
	unsigned char B4b3:1;
	unsigned char B4b4:1;
	unsigned char B4b5:1;
	unsigned char B4b6:1;
	unsigned char B4b7:1;
	unsigned char B4b8:1;

	unsigned char B5b1:1;
	unsigned char B5b2:1;
	unsigned char B5b3:1;
	unsigned char B5b4:1;
	unsigned char B5b5:1;
	unsigned char B5b6:1;
	unsigned char B5b7:1;
	unsigned char B5b8:1;
#endif
} EMV_BITS;

extern EMV_BITS* libemv_TVR;
extern EMV_BITS* libemv_TSI;
extern EMV_BITS* libemv_capa;
extern EMV_BITS* libemv_addi_capa;

#endif // __INTERNAL_H
