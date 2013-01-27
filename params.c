#include "include/libemv.h"
#include "internal.h"
#include <string.h>

char (*libemv_ext_apdu)(unsigned char cla, unsigned char ins, unsigned char p1, unsigned char p2,
				   unsigned char dataSize, const unsigned char* data,
				   int* outDataSize, unsigned char* outData);

void* (*libemv_malloc)(size_t size);
void* (*libemv_realloc)(void* ptr, size_t size);
void (*libemv_free)(void * ptr);

void (*libemv_get_date)(char* strdate);
void (*libemv_get_time)(char* strtime);

int (*libemv_rand)(void);

int (*libemv_printf)(const char * format, ...);

char libemv_debug_enabled;

LIBEMV_API void libemv_set_debug_enabled(char enabled)
{
	libemv_debug_enabled = enabled;
}

LIBEMV_API void set_function_apdu(char (*f_apdu)(unsigned char cla, unsigned char ins, unsigned char p1, unsigned char p2,
								  unsigned char dataSize, const unsigned char* data,
								  int* outDataSize, unsigned char* outData))
{
	libemv_ext_apdu = f_apdu;
}

LIBEMV_API void set_function_malloc(void* (*f_malloc)(size_t size))
{
	libemv_malloc = f_malloc;
}

LIBEMV_API void set_function_realloc(void* (*f_realloc)(void* ptr, size_t size))
{
	libemv_realloc = f_realloc;
}

LIBEMV_API void set_function_free(void (*f_free)(void * ptr))
{
	libemv_free = f_free;
}

LIBEMV_API void set_function_get_date_YYMMDD(void (*f_get_date)(char* strdate))
{
	libemv_get_date = f_get_date;
}

LIBEMV_API void set_function_get_date_HHmmss(void (*f_get_time)(char* strtime))
{
	libemv_get_time = f_get_time;
}

LIBEMV_API void set_function_rand(int (*f_rand)(void))
{
	libemv_rand = f_rand;
}

LIBEMV_API void set_function_debug_printf(int (*f_printf)(const char * format, ...))
{
	libemv_printf = f_printf;
}

LIBEMV_SETTINGS libemv_settings;
LIBEMV_GLOBAL libemv_global;
int libemv_applications_count;
LIBEMV_APPLICATIONS* libemv_applications;

void libemv_destroy_settings(void)
{
	if (libemv_applications)
		libemv_free(libemv_applications);
}

LIBEMV_API void libemv_set_library_settings(LIBEMV_SETTINGS* settings)
{
	memcpy(&libemv_settings, settings, sizeof(LIBEMV_SETTINGS));
}

LIBEMV_API void libemv_set_global_settings(LIBEMV_GLOBAL* settings)
{
	memcpy(&libemv_global, settings, sizeof(LIBEMV_GLOBAL));
}

LIBEMV_API void set_applications_data(LIBEMV_APPLICATIONS* apps, int countApps)
{
	if (libemv_applications)
		libemv_free(libemv_applications);
	libemv_applications = libemv_malloc(countApps * sizeof(LIBEMV_APPLICATIONS));
	memcpy(libemv_applications, apps, countApps * sizeof(LIBEMV_APPLICATIONS));
	libemv_applications_count = countApps;
}
