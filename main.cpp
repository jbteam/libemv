#include <stdio.h>
#include <string.h>
#include <time.h>
#include <Winscard.h>
#include "include/libemv.h"

SCARDHANDLE hCardHandle;

extern "C" char f_apdu(unsigned char cla, unsigned char ins, unsigned char p1, unsigned char p2,
					  unsigned char dataSize, const unsigned char* data,
					  int* outDataSize, unsigned char* outData)
{
	BYTE pbRecv[256] = {0};
	DWORD dwRecv = 256;
	BYTE pbSend[256] = {cla, ins, p1, p2, dataSize};
	memcpy(pbSend + 5, data, dataSize);
	DWORD dwSend = 5 + dataSize;
	LONG lReturn = SCardTransmit(hCardHandle,
		SCARD_PCI_T0,
		pbSend,
		dwSend,
		NULL,
		pbRecv,
		&dwRecv );
	if ( SCARD_S_SUCCESS != lReturn )
	{
		printf("Failed SCardTransmit\n");
		return 0;
	}
	if (dwRecv >= 2 && pbRecv[0] == 0x6C)
	{
		BYTE pbSend2[256] = {cla, ins, p1, p2, pbRecv[1]};
		DWORD dwSend = 5;
		dwRecv = 256;
		LONG lReturn = SCardTransmit(hCardHandle,
			SCARD_PCI_T0,
			pbSend2,
			dwSend,
			NULL,
			pbRecv,
			&dwRecv );
		if ( SCARD_S_SUCCESS != lReturn )
		{
			printf("Failed SCardTransmit\n");
			return 0;
		}
	}
	if (dwRecv >= 2 && pbRecv[0] == 0x61)
	{
		BYTE pbSend2[256] = {0x00, 0xC0, 0x00, 0x00, pbRecv[1]};
		DWORD dwSend = 5;
		dwRecv = 256;
		LONG lReturn = SCardTransmit(hCardHandle,
			SCARD_PCI_T0,
			pbSend2,
			dwSend,
			NULL,
			pbRecv,
			&dwRecv );
		if ( SCARD_S_SUCCESS != lReturn )
		{
			printf("Failed SCardTransmit\n");
			return 0;
		}
	}
	memcpy(outData, pbRecv, dwRecv);
	*outDataSize = dwRecv;
	return 1;
}

int main(int argc, char **argv)
{
	SCARDCONTEXT    hSC;
	LONG            lReturn;
	// Establish the context.
	lReturn = SCardEstablishContext(SCARD_SCOPE_USER,
		NULL,
		NULL,
		&hSC);
	if ( SCARD_S_SUCCESS != lReturn )
	{
		printf("Failed SCardEstablishContext\n");
		return 1;
	}

	LPTSTR          pmszReaders = NULL;
	DWORD           cch = SCARD_AUTOALLOCATE;	

	lReturn = SCardListReaders(hSC,
		NULL,
		(LPTSTR)&pmszReaders,
		&cch );

	if (lReturn != SCARD_S_SUCCESS || *pmszReaders == '\0')
	{
		printf("No readers\n");
		return 1;
	}
	
	DWORD           dwAP;
	lReturn = SCardConnect( hSC, 
		(LPCTSTR)pmszReaders,
		SCARD_SHARE_SHARED,
		SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
		&hCardHandle,
		&dwAP );
	SCardFreeMemory( hSC, pmszReaders );
	if ( SCARD_S_SUCCESS != lReturn )
	{
		lReturn = SCardReconnect(hCardHandle,
			SCARD_SHARE_SHARED,
			SCARD_PROTOCOL_T0 | SCARD_PROTOCOL_T1,
			SCARD_LEAVE_CARD,
			&dwAP );
		if ( SCARD_S_SUCCESS != lReturn )
		{
			printf("Failed SCardReconnect\n");
			return 1;
		}
	}

	// Use the connection.
	// Display the active protocol.
	switch ( dwAP )
	{
	case SCARD_PROTOCOL_T0:
		printf("Active protocol T0\n"); 
		break;

	case SCARD_PROTOCOL_T1:
		printf("Active protocol T1\n"); 
		break;

	case SCARD_PROTOCOL_UNDEFINED:
	default:
		printf("Active protocol unnegotiated or unknown\n"); 
		break;
	}

	TCHAR           szReader[200];
	cch = 200;
	BYTE            bAttr[32];
	DWORD           cByte = 32;
	DWORD           dwState, dwProtocol;

	// Determine the status.
	// hCardHandle was set by an earlier call to SCardConnect.
	lReturn = SCardStatus(hCardHandle,
		szReader,
		&cch,
		&dwState,
		&dwProtocol,
		(LPBYTE)&bAttr,
		&cByte); 

	if ( SCARD_S_SUCCESS != lReturn )
	{
		printf("Failed SCardStatus\n");
		return 1;
	}

	// Examine retrieved status elements.
	// Look at the reader name and card state.
	printf("%S\n", szReader );
	switch ( dwState )
	{
	case SCARD_ABSENT:
		printf("Card absent.\n");
		break;
	case SCARD_PRESENT:
		printf("Card present.\n");
		break;
	case SCARD_SWALLOWED:
		printf("Card swallowed.\n");
		break;
	case SCARD_POWERED:
		printf("Card has power.\n");
		break;
	case SCARD_NEGOTIABLE:
		printf("Card reset and waiting PTS negotiation.\n");
		break;
	case SCARD_SPECIFIC:
		printf("Card has specific communication protocols set.\n");
		break;
	default:
		printf("Unknown or unexpected card state.\n");
		break;
	}

	srand((unsigned int) time(NULL));
	libemv_init();

	libemv_set_debug_enabled(1);
	set_function_apdu(f_apdu);

	// Global settings
	LIBEMV_GLOBAL globalSettings = {"12345678", {0x08, 0x40}, {0xC1, 0x00, 0xF0, 0xA0, 0x01}, {0xE0, 0xF8, 0xE8}, 0x22};
	libemv_set_global_settings(&globalSettings);

	LIBEMV_APPLICATIONS visa;
	memset(&visa, 0, sizeof(visa));
	memcpy(visa.RID, "\xA0\x00\x00\x00\x03", 5);
	
	LIBEMV_AID visa1010 = {7, {0xA0, 0x00, 0x00, 0x00, 0x03, 0x10, 0x10}, 1};
	LIBEMV_AID visa2010 = {7, {0xA0, 0x00, 0x00, 0x00, 0x03, 0x20, 0x10}, 1};
	LIBEMV_AID visa2020 = {7, {0xA0, 0x00, 0x00, 0x00, 0x03, 0x20, 0x20}, 1};
	LIBEMV_AID visa8010 = {7, {0xA0, 0x00, 0x00, 0x00, 0x03, 0x80, 0x10}, 1};
	visa.aidsCount = 4;
	visa.aids[0] = visa1010;
	visa.aids[1] = visa2010;
	visa.aids[2] = visa2020;
	visa.aids[3] = visa8010;

	set_applications_data(&visa, 1);

	if (libemv_is_emv_ATR(bAttr, cByte))
		printf("ATR ok.\n");
	else
		printf("ATR wrong.\n");

	int resultBuildCand = libemv_build_candidate_list();
	if (resultBuildCand != LIBEMV_OK)
		return 0;

	while (1)
	{
		int resultSelectApplication = libemv_application_selection();
		if (resultSelectApplication < 0)
			return 0;
		
		if (resultSelectApplication == LIBEMV_NEED_CONFIRM_APPLICATION)
		{
			printf("Confirm select app %s (y/n): ", libemv_get_candidate(0)->strApplicationLabel);
			if (getchar() != 'y')
				return 0;
			if (libemv_select_application(0) != LIBEMV_OK)
				continue;
		}
		
		if (resultSelectApplication == LIBEMV_NEED_SELECT_APPLICATION)
		{
			printf("Select application from list:\n");
			for (int idx = 0; idx < libemv_count_candidates(); idx++)
			{
				printf("%d (priority %d) - %s\n", idx, libemv_get_candidate(idx)->priority, libemv_get_candidate(idx)->strApplicationLabel);
			}
			printf("Index: ");
			int indexSelect = getchar() - '0';
			if (libemv_select_application(indexSelect) != LIBEMV_OK)
				continue;
		}

		// Application selected ok, get processing option
		int resultProcessingOption = libemv_get_processing_option();
		if (resultProcessingOption != LIBEMV_OK)
			continue;

		break;
	}

	int resultReadApp = libemv_read_app_data();
	if (resultReadApp != LIBEMV_OK)
		return 0;

	// Debug out buffer
	{
		int shift = 0;
		unsigned short tag;
		unsigned char* data;
		int length;
		printf("\nApp buffer:\n");
		while ((shift = libemv_get_next_tag(shift, &tag, &data, &length)) != 0)
		{
			bool isAscii = true;
			printf("- %4X [%d]: {", tag, length);
			for (int idx = 0; idx < length; idx++)
			{
				printf("%02X, ", data[idx] & 0xFF);
				if (data[idx] < ' ' || data[idx] > 0x7E)
					isAscii = false;
			}
			printf("}\n");
			if (isAscii)
			{
				char* strData = new char[length + 1];
				strData[length] = 0;
				memcpy(strData, data, length);
				printf("ascii: %s\n", strData);
				delete[] strData;
			}
		}
	}

	return 0;
}
