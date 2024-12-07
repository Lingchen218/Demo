
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include<stdint.h>
#include "crc32.h"
uint32_t crc32_table[256];

int make_crc32_table()
{
	uint32_t c;
	int i = 0;
	int bit = 0;

	for (i = 0; i < 256; i++)
	{
		c = (uint32_t)i;

		for (bit = 0; bit < 8; bit++)
		{
			if (c & 1)
			{
				c = (c >> 1) ^ (0xEDB88320);
			}
			else
			{
				c = c >> 1;
			}

		}
		crc32_table[i] = c;
	}
	return 1;

}

uint32_t make_crc( unsigned char* string, uint32_t size)
{
	uint32_t crc = 0xffffffff;
	make_crc32_table();
	while (size--)
		crc = (crc >> 8) ^ (crc32_table[(crc ^ *string++) & 0xff]);

	return crc;
}
