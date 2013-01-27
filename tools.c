#include "include/libemv.h"
#include "internal.h"
#include <string.h>

void libemv_debug_buffer(char* strPre, unsigned char* buf, int size, char* strPost)
{
	int i;
	libemv_printf(strPre);
	for (i = 0; i < size; i++)
	{
		libemv_printf("%02X", buf[i] & 0xFF);
		if (i != size - 1)
			libemv_printf(", ");
	}
	libemv_printf(strPost);
}
