#ifndef __LIBEMV_H
#define __LIBEMV_H

// For size_t type
#include <stddef.h>

#ifdef __cplusplus
extern "C"
{
#endif

// Static lib
#define LIBEMV_API

// Init function, run it once on the start program or before using libemv
// Warning: don't call this function after any other libemv functions,
// because this function clears all libemv data!
// If you use standart rand(), don't forget to initialize random: srand() before using libemv
LIBEMV_API void libemv_init(void);

// Call this function at the end of your program
LIBEMV_API void libemv_destroy(void);

// Enable, disable debug output. Default: disabled.
// enabled: 1 enable, 0 disable
// Don't use debug in production versions
LIBEMV_API void libemv_set_debug_enabled(char enabled);

// Required definition
// The function f_apdu() must return: 0 communication error, 1 success
LIBEMV_API void set_function_apdu(char (*f_apdu)(unsigned char cla, unsigned char ins, unsigned char p1, unsigned char p2,
								  unsigned char dataSize, const unsigned char* data,
								  int* outDataSize, unsigned char* outData));

// Heap functions. Default: malloc(), realloc(), free()
LIBEMV_API void set_function_malloc(void* (*f_malloc)(size_t size));
LIBEMV_API void set_function_realloc(void* (*f_realloc)(void* ptr, size_t size));
LIBEMV_API void set_function_free(void (*f_free)(void * ptr));

// Functions of getting current date and time
// Output must be null terminated C string, hour 24-format, for example:
// 28 September 2012 15:25:32, strdate: "120928", strtime: "152532"
// Default: time(), strftime()
LIBEMV_API void set_function_get_date_YYMMDD(void (*f_get_date)(char* strdate));
LIBEMV_API void set_function_get_date_HHmmss(void (*f_get_time)(char* strtime));

// Function must return random number at least from 0 to 32767 (RAND_MAX)
LIBEMV_API void set_function_rand(int (*f_rand)(void));

// Debug output function
LIBEMV_API void set_function_debug_printf(int (*f_printf)(const char * format, ...));

// Check ATR, detect whether ATR apply to emv card
// Return: 1 ok, 0 wrong ATR
LIBEMV_API char libemv_is_emv_ATR(unsigned char* bufATR, int size);

// Get tag value from application buffer
// Return: pointer, memory allocated in buffer; return 0 if not found
LIBEMV_API unsigned char* libemv_get_tag(unsigned short tag, int* outSize);

// Get next data from application buffer using some shift value
// Returns shift for next element or 0 if end is reached
int libemv_get_next_tag(int shift, unsigned short* outTag, unsigned char** outBuffer, int* outSize);

// Settings of library, optional
typedef struct
{
	char appSelectionUsePSE;			// 1 - if use PSE, 0 - don't use PSE
	char appSelectionSupportConfirm;	// 1 - if support cardholder confirmation of application, 0 - not support
	char appSelectionPartial;			// 1 - if support partial AID selection
	char appSelectionSupport;			// 1 - if the terminal supports the ability to allow the cardholder to select an application
} LIBEMV_SETTINGS;

// Set above settings to libemv
LIBEMV_API void libemv_set_library_settings(LIBEMV_SETTINGS* settings);

// Settings global, EMV book 4, Application Independent Data
typedef struct 
{
	char strIFDSerialNumber[9];							// Ex. "12345678"
	unsigned char terminalCountryCode[2];				// Ex. {0x08, 0x40}
	unsigned char additionalTerminalCapabilities[5];	// Ex. {0xC1, 0x00, 0xF0, 0xA0, 0x01}
	unsigned char terminalCapabilities[3];				// Ex. {0xE0, 0xF8, 0xE8}
	unsigned char terminalType;							// Ex. 0x22
} LIBEMV_GLOBAL;

// Set above settings to libemv
LIBEMV_API void libemv_set_global_settings(LIBEMV_GLOBAL* settings);

// Structure of one AID
typedef struct
{
	int aidLength;						// Length in bytes, Ex. 7
	unsigned char aid[16];				// Ex. {0xA0, 0x00, 0x00, 0x00, 0x00, 0x10, 0x10}
	char applicationSelectionIndicator;	// Application Selection Indicator, 0 - if application must match AID exactly, 1 - if allow partial
} LIBEMV_AID;

// Structure of one Certification Authority Public Key
typedef struct
{
	int keySize;							// Size of public key in bits. Ex. 1152
	unsigned char keyExponent[3];			// Ex. {0x00, 0x00, 0x03}
	unsigned char keyModulus[248];			// Modulus of public key, maximum: 248 x 8 = 1984 bits
	unsigned char keyIndex;					// Certification Authority Public Key Index
	unsigned char checkSum[20];				// A check value calculated on the concatenation of all parts of the Certification Authority Public Key
} LIEBEMV_AUTHORITY_PUBLIC_KEY;

// Settings global, EMV book 4, Application Dependent Data
typedef struct
{
	unsigned char RID[5];								// Registered Application Provider Identifier, Ex. {0xA0, 0x00, 0x00, 0x00, 0x03}
	int aidsCount;										// Count of AIDs in this configuration
	LIBEMV_AID aids[20];								// AIDs of current configuration
	char strAcquirerIdentifier[7];						// Ex. "100200"
	unsigned char applicationVersionNumber[2];			// Ex. {0x00, 0x8C}
	int publicKeysCount;								// Count of public keys in this configuration, see next element
	LIEBEMV_AUTHORITY_PUBLIC_KEY publicKeys[10];		// Public keys, see structure LIEBEMV_AUTHORITY_PUBLIC_KEY
	int defaultDDOLSize;								// Size in bytes of next element. 0 - if default DDOL is empty
	unsigned char defaultDDOL[64];						// data of default DDOL with size defaultDDOLSize
	int defaultTDOLSize;								// Size in bytes of next element. 0 - if default TDOL is empty
	unsigned char defaultTDOL[64];						// data of default TDOL with size defaultTDOLSize
	int maxTargetForBiasedRandomSelection;				// Maximum Target Percentage to be Used for Biased Random Selection (also in the range of 0 to 99 but at least as high as the previous ‘Target Percentage to be Used for Random Selection’).
	unsigned char merchantCategoryCode[2];				// Merchant Category Code, Ex. {0x30, 0x01}
	char strMerchantIdentifier[16];						// Merchant Identifier, Ex. "000000000018003"
	char strMerchantNameAndLocation[96];				// Null terminated C string, Ex. "202B, USELU LAGOS ROAD BENIN CITY"
	int targetForRandomSelection;						// Target Percentage to be Used for Random Selection (in the range of 0 to 99)
	unsigned char terminalActionCodeDefault[5];			// Terminal Action Code - Default
	unsigned char terminalActionCodeDenial[5];			// Terminal Action Code - Denial
	unsigned char terminalActionCodeOnline[5];			// Terminal Action Code - Online
	unsigned char terminalFloorLimit[4];				// Terminal Floor Limit, Ex. {0x00, 0x00, 0x10, 0x00} - value 10.00
	char strTerminalIdentification[9];					// Designates the unique location of a terminal at a merchant, Ex. "EMVPOS4 "
	int terminalRiskManagementDataSize;					// Size of next element
	unsigned char terminalRiskManagementData[8];		// Application-specific value used by the card for risk management purposes
	unsigned char thresholdValueForRandomSelection[4];	// Threshold Value for Biased Random Selection (which must be zero or a positive number less than the floor limit)
	unsigned char transactionReferenceCurrency[2];		// Transaction Reference Currency Code, Ex. {0x09, 0x78}
	unsigned char transactionReferenceCurrencyConv[4];	// Factor used in the conversion from the Transaction Currency Code to the Transaction Reference Currency Code
	unsigned char transactionReferenceCurrencyExponent;	// Indicates the implied position of the decimal point from the right of the transaction amount, with the Transaction Reference Currency Code represented according to ISO 4217
} LIBEMV_APPLICATIONS;

// Set list of application and its settings supported by terminal
LIBEMV_API void set_applications_data(LIBEMV_APPLICATIONS* apps, int countApps);

// Application info for select application
typedef struct
{
	int DFNameLength;
	unsigned char DFName[16];				// byte data with size DFNameLength
	char strApplicationLabel[17];			// Null terminated c string
	char needCardholderConfirm;				// 1 - need confirm, 0 - selection without confirmation
	int priority;							// 0 - no priority, else ranging from 1–15, with 1 being highest priority
	char strLanguagePreference[9];			// Null terminated c string, 1-4 languages stored in order of preference, each represented by 2 alphabetical characters according to ISO 639
	unsigned char issuerCodeTableIndex;		// Indicates the code table according to ISO/IEC 8859 for displaying the Application Preferred Name
	char strApplicationPreferredName[17];	// Preferred mnemonic associated with the AID, codepage: issuerCodeTableIndex
	int indexRID;							// For internal use
} LIBEMV_SEL_APPLICATION_INFO;

// Results of "transaction flow" functions
// Can be error or request some action, e.g. request pin
#define LIBEMV_OK						0	// Ok result
#define LIBEMV_NEED_CONFIRM_APPLICATION	1	// Cardholder must confirm application
#define LIBEMV_NEED_SELECT_APPLICATION	2	// Cardholder must selection application from application list
#define LIBEMV_UNKNOWN_ERROR			-1	// Some other error
#define LIBEMV_ERROR_TRANSMIT			-2	// Communication error
#define LIBEMV_NOT_SUPPORTED			-3	// The command is not supported by the ICC (SW1 SW2 = '6A81'), the terminal terminates the card session
#define LIBEMV_TERMINATED				-4	// Transaction is terminated
#define LIBEMV_NOT_SATISFIED			-5	// Get processing option failed

// Transaction flow. Build candidate list
// Result (return value) can be:
// LIBEMV_OK, LIBEMV_UNKNOWN_ERROR, LIBEMV_ERROR_TRANSMIT, LIBEMV_NOT_SUPPORTED
LIBEMV_API int libemv_build_candidate_list(void);

// Transaction flow. Final Selection
// Result can be:
// LIBEMV_OK - ok, application was selected, call libemv_get_processing_option to process next step
// LIBEMV_NEED_CONFIRM_APPLICATION - cardholder must confirm application before it will be selected, call libemv_get_candidate(0)
// LIBEMV_NEED_SELECT_APPLICATION - cardholder must selection application from application list, call libemv_count_candidates() and libemv_get_candidate(index)
// LIBEMV_TERMINATED, LIBEMV_ERROR_TRANSMIT, LIBEMV_UNKNOWN_ERROR
LIBEMV_API int libemv_application_selection(void);

// Transaction flow. Final Selection
// User select application manually or confirm selection application
// indexApplication - index can be from 0 to libemv_count_candidates() - 1
// For confirm it always = 0
// Result can be:
// LIBEMV_OK - ok, application was selected, call libemv_get_processing_option to process next step
// LIBEMV_ERROR_TRANSMIT, LIBEMV_UNKNOWN_ERROR
LIBEMV_API int libemv_select_application(int indexApplication);

// Get application candidates count (for select)
LIBEMV_API int libemv_count_candidates(void);

// Get candidate using index
LIBEMV_API LIBEMV_SEL_APPLICATION_INFO* libemv_get_candidate(int indexApplication);

// Transaction flow. Get processing option
// Result can be:
// LIBEMV_OK - ok, you can process next step
// LIBEMV_NOT_SATISFIED, LIBEMV_ERROR_TRANSMIT, LIBEMV_UNKNOWN_ERROR
LIBEMV_API int libemv_get_processing_option(void);

// Transaction flow. Read Application Data
// Result can be:
// LIBEMV_OK - ok, you can process next step and use libemv_get_tag to get some tags (for ex. PAN)
// LIBEMV_TERMINATED, LIBEMV_ERROR_TRANSMIT, LIBEMV_UNKNOWN_ERROR
LIBEMV_API int libemv_read_app_data(void);

/*
libemv_build_candidate_list
while (1)
{
  app selection
    get apps
	select
  get processing options: ok, need_app_selection
}
*/

#ifdef __cplusplus
};
#endif

#endif // __LIBEMV_H
