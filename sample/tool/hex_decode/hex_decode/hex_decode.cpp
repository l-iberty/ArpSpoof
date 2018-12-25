#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>

char code[] = { 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 0xa, 0xb, 0xc, 0xd, 0xe, 0xf };

int main(int argc, char *args[])
{
	if (argc != 2)
	{
		printf("usage: %s <file_name>\n", args[0]);
		return 0;
	}

	FILE *fp_in, *fp_out;
	char hex[2];
	char ch;

	if ((fp_in = fopen(args[1], "rb")) == NULL ||
		(fp_out = fopen("binfile", "wb")) == NULL)
	{
		printf("invalid file\n");
		return 0;
	}

	while (!feof(fp_in))
	{
		// read a hex
		hex[0] = fgetc(fp_in);
		hex[1] = fgetc(fp_in);
		if (hex[0] == -1 || hex[1] == -1)
			break;

		if (hex[0] >= '0' && hex[0] <= '9')
			hex[0] = code[hex[0] - '0'];
		else
			hex[0] = code[hex[0] - 'a' + 10];

		if (hex[1] >= '0' && hex[1] <= '9')
			hex[1] = code[hex[1] - '0'];
		else
			hex[1] = code[hex[1] - 'a' + 10];

		ch = (hex[0] << 4) | hex[1];
		// write to bin file
		fwrite(&ch, sizeof(ch), 1, fp_out);
	}
	fclose(fp_in);
	fclose(fp_out);
}