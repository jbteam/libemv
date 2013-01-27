#include "include/libemv.h"
#include "internal.h"
#include <string.h>

// Application buffer, from ICC and terminal
// ([unsigned short tag][int length][data]..)
static unsigned char* tlv_buffer;
static int tlv_allocated;
static int tlv_length;

void libemv_init_tlv_buffer(void)
{
	tlv_buffer = 0;
	tlv_allocated = 0;
	tlv_length = 0;
}

void libemv_destroy_tlv_buffer(void)
{
	if (tlv_buffer)
		libemv_free(tlv_buffer);
}

static void check_and_reserve_buffer(int incrSize)
{
	if (tlv_length + incrSize <= tlv_allocated)
		return;

	if (tlv_allocated == 0)
	{
		// Init size
		tlv_allocated = 2 * 1024;
		tlv_buffer = libemv_malloc(tlv_allocated);
	} else
	{
		// incrSize musn't very big, but just in case
		while (tlv_length + incrSize > tlv_allocated)
			tlv_allocated *= 2;
		// Realloc must copy old data
		tlv_buffer = libemv_realloc(tlv_buffer, tlv_allocated);
	}

	// Unable allocate
	if (tlv_buffer == 0)
	{
		if (libemv_debug_enabled)
			libemv_printf("Unable allocate memory\n");
	}
}

LIBEMV_API unsigned char* libemv_get_tag(unsigned short tag, int* outSize)
{
	unsigned char* currBuf;
	int currPos;	

	currBuf = tlv_buffer;
	currPos = 0;
	while (currPos < tlv_length)
	{
		unsigned short currTag;
		int currLength;

		// Corrupted buffer
		if (currPos + (int) sizeof(unsigned short) + (int) sizeof(int) > tlv_length)
		{
			if (libemv_debug_enabled)
				libemv_printf("tlv buffer malfunc\n");
			break;
		}

		memcpy(&currTag, currBuf, sizeof(unsigned short));
		currBuf += sizeof(unsigned short);
		currPos += sizeof(unsigned short);
		memcpy(&currLength, currBuf, sizeof(int));
		currBuf += sizeof(int);
		currPos += sizeof(int);
		if (currTag == tag)
		{
			*outSize = currLength;
			return currBuf;
		}
		currBuf += currLength;
		currPos += currLength;
	}

	// Not found
	return 0;
}

int libemv_get_next_tag(int shift, unsigned short* outTag, unsigned char** outBuffer, int* outSize)
{
	int sh;
	sh = shift;

	// Tag
	if (sh + (int) sizeof(unsigned short) > tlv_length)
		return 0;
	memcpy(outTag, tlv_buffer + sh, sizeof(unsigned short));
	sh += sizeof(unsigned short);

	// Length
	if (sh + (int) sizeof(int) > tlv_length)
		return 0;
	memcpy(outSize, tlv_buffer + sh, sizeof(int));
	sh += sizeof(int);

	// Value
	if (sh + *outSize > tlv_length)
		return 0;
	*outBuffer = tlv_buffer + sh;
	sh += *outSize;

	return sh;
}

void libemv_set_tag(unsigned short tag, unsigned char* data, int size)
{
	unsigned char* findData;
	int findDataSize;
	findData = libemv_get_tag(tag, &findDataSize);
	if (findData)
	{
		// Replace data
		if (findDataSize == size)
		{
			// Size didn't change, just copy buffer
			memcpy(findData, data, size);
		} else
		{
			// Reserve memory and move data
			check_and_reserve_buffer(size - findDataSize);
			memmove(findData + size, findData + findDataSize, tlv_length - (findData - tlv_buffer) - findDataSize);
			memcpy(findData - sizeof(int), &size, sizeof(int));
			memcpy(findData, data, size);
			tlv_length += size - findDataSize;
		}
	} else
	{
		unsigned char* endBuffer;
		// Add data to the end of buffer
		check_and_reserve_buffer(sizeof(unsigned short) + sizeof(int) + size);
		endBuffer = tlv_buffer + tlv_length;
		memcpy(endBuffer, &tag, sizeof(unsigned short));
		endBuffer += sizeof(unsigned short);
		memcpy(endBuffer, &size, sizeof(int));
		endBuffer += sizeof(int);
		memcpy(endBuffer, data, size);
		tlv_length += sizeof(unsigned short) + sizeof(int) + size;
	}
}

void libemv_clear_tlv_buffer(void)
{
	tlv_length = 0;
}

int libemv_parse_tlv(unsigned char* inBuffer, int inBufferSize, unsigned short* outTag, unsigned char** outBuffer, int* outSize)
{
	unsigned char* buf;
	int bufSize;
	buf = inBuffer;
	bufSize = inBufferSize;

	// 1 byte tag
	if (bufSize <= 0)
		return 0;
	*outTag = *buf;	
	if ((*buf & 0x1F) == 0x1F)
	{
		// 2 byte tag
		buf++;
		bufSize--;
		if (bufSize <= 0)
			return 0;

		// Check "Another byte follows"
		if (*buf & 0x80)
			return 0;
		*outTag <<= 8;
		*outTag |= *buf;
	}
	buf++;
	bufSize--;

	// 1 byte length
	if (bufSize <= 0)
		return 0;
	if (*buf & 0x80)
	{
		int nBytes = *buf & 0x7F;
		// Next bytes length
		*outSize = 0;
		while (nBytes--)
		{
			buf++;
			bufSize--;
			if (bufSize <= 0)
				return 0;
			*outSize <<= 8;
			*outSize |= *buf;
		}
	} else
	{
		*outSize = *buf;		
	}
	buf++;
	bufSize--;

	// Check size more than input size or max size
	if (inBufferSize < *outSize + (buf - inBuffer))
		return 0;

	// Point data and return
	*outBuffer = buf;
	return *outSize + (buf - inBuffer);
}

int libemv_make_tlv(unsigned char* inBuffer, int inBufferSize, unsigned short tag, unsigned char* tlvBuffer)
{
	int tlvSize;
	tlvSize = 0;
	if ((tag & 0x1F00) == 0x1F00)
	{
		// 2 byte tag
		tlvBuffer[tlvSize++] = (tag >> 8) & 0xFF;
		tlvBuffer[tlvSize++] = tag & 0xFF;
	} else
	{
		// 1 byte tag
		tlvBuffer[tlvSize++] = tag & 0xFF;
	}

	if (inBufferSize > 0x7F)
	{
		// n byte length
		int n;
		if (inBufferSize < 0x100)
			n = 1;
		else if (inBufferSize < 0x10000)
			n = 2;
		else if (inBufferSize < 0x1000000)
			n = 3;
		else
			n = 4;
		n |= 0x80;
		tlvBuffer[tlvSize++] = n & 0xFF;
		while (n--)
		{
			tlvBuffer[tlvSize++] = (inBufferSize >> (n * 8)) & 0xFF;
		}
	} else
	{
		// 1 byte length
		tlvBuffer[tlvSize++] = inBufferSize & 0x7F;
	}

	// Copy data
	memcpy(tlvBuffer + tlvSize, inBuffer, inBufferSize);
	tlvSize += inBufferSize;

	return tlvSize;
}

int libemv_dol(unsigned char* dol, int dolSize, unsigned char* outBuffer)
{
	int outSize;
	int dolShift;
	outSize = 0;
	dolShift = 0;
	while (dolShift < dolSize)
	{
		unsigned short tag;
		int size;
		unsigned char* findData;
		int findSize;
		int sizeToCopy;

		// Tag could be 1 or 2 byte
		tag = dol[dolShift];
		if ((dol[dolShift] & 0x1F) == 0x1F)
		{
			dolShift++;
			if (dolShift >= dolSize)
				break;
			tag <<= 8;
			tag |= dol[dolShift];
		}
		dolShift++;
		if (dolShift >= dolSize)
			break;

		// Length could be only 1 byte
		size = dol[dolShift];
		dolShift++;

		// Copy data
		findData = libemv_get_tag(tag, &findSize);
		if (!findData)
			findSize = 0;
		sizeToCopy = findSize < size ? findSize : size;
		if (findData)
		{
			memcpy(outBuffer + outSize, findData, sizeToCopy);
			outSize += sizeToCopy;
		}
		if (size > findSize)
		{
			memset(outBuffer + outSize, 0, size - findSize);
			outSize += size - findSize;
		}
	}

	return outSize;
}
