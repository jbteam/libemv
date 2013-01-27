#include "include/libemv.h"
#include "internal.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

static void init_functions(void);
static void get_transaction_date_YYMMDD(char* strdate);
static void get_transaction_time_HHmmss(char* strtime);

// This function can cause problems in custom platforms
static void init_functions(void)
{
	libemv_ext_apdu = 0;

	libemv_malloc = malloc;
	libemv_realloc = realloc;
	libemv_free = free;

	libemv_get_date = get_transaction_date_YYMMDD;
	libemv_get_time = get_transaction_time_HHmmss;

	libemv_rand = rand;

	libemv_printf = printf;
}

// This function can cause problems in custom platforms
static void get_transaction_date_YYMMDD(char* strdate)
{
	time_t rawtime;
	time(&rawtime);
	strftime(strdate, 6, "%y%m%d", localtime(&rawtime));
}

// This function can cause problems in custom platforms
static void get_transaction_time_HHmmss(char* strtime)
{
	time_t rawtime;
	time(&rawtime);
	strftime(strtime, 6, "%H%M%S", localtime(&rawtime));
}

LIBEMV_API void libemv_init(void)
{
	init_functions();
	libemv_debug_enabled = 0;

	libemv_init_tlv_buffer();

	// Settings
	memset(&libemv_settings, 0, sizeof(libemv_settings));
	memset(&libemv_global, 0, sizeof(libemv_global));
	libemv_applications_count = 0;
	libemv_applications = 0;
	libemv_settings.appSelectionUsePSE = 1;
	libemv_settings.appSelectionSupportConfirm = 1;
	libemv_settings.appSelectionPartial = 1;
	libemv_settings.appSelectionSupport = 1;
}

LIBEMV_API void libemv_destroy(void)
{
	if (libemv_debug_enabled)
		libemv_printf("Destroy allocated data...\n");
	libemv_destroy_tlv_buffer();
	libemv_destroy_settings();
}
