#define init policy_sample_LTX_init
#define on_resolve_request policy_sample_LTX_on_resolve_request
#define on_connect_request policy_sample_LTX_on_connect_request

#include <stdio.h>

int init()
{
	printf("Policy sample library has been loaded.\n");
	return 0;
}

int on_resolve_request()
{
	printf("Resolve request handled by policy sample library\n");
	return 0;
}

int on_connect_request()
{
	printf("Connect request handled by policy sample library\n");
	return 0;
}
