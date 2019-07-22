#include "ResourceInjector.h"

int main(int argc, CHAR *argv[])
{
	if (argc != 3) {
		printf("Arguments are: process_name - library_path");
		return 0;
	}

	InjectLibrary(argv[1], argv[2]);
}