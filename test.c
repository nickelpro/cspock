#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "mcp.h"

int main(int argc, char *argv[]) {
	mcp_meta_t mymeta;
	mymeta.type_id = MCP_METAARR_T;
	mymeta.arr[0] = 5;
	printf("Metadata type is: %d and val is: %d\n", mymeta.type_id, mymeta.arr[0]);
	return 0;
}
