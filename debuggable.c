#include <stdlib.h>
#include <unistd.h>

int main(int argc, char *argv[])
{
	sleep(strtol(argv[1], NULL, 0));
	return 0;
}
