#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include "mcp.h"

int main(int argc, char *argv[]) {
	mcp_meta_t mymeta;
	mcp_meta_t ref;
	mymeta.next = &ref;
	return 0;
}
