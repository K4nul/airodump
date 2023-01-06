#include "CAirodump.h"
#include <iostream>
#include <stdbool.h>
#include <stdio.h>


void usage() {
	printf("syntax: pcap-test <interface>\n");
	printf("sample: pcap-test wlan0\n");
}

bool parse(int argc, char* argv[]) {
	if (argc != 2) {
		usage();
		return false;
	}
	return true;
}

int main(int argc, char* argv[]) {
	if (!parse(argc, argv))
		return -1;

	CAirodump airodump;
	airodump.airodump(argv[1]);

	return 0;
}
