#include "CAirodump.h"

CAirodump::CAirodump(){}
CAirodump::~CAirodump(){}

int CAirodump::airodump(char * dev)
{
    param.dev_ = dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap_t* pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
		return -1;
	}

    while(1)
    {
        int status = getWirelessPacket(pcap);
        if (status == FAIL)
            break; 
        if (status == NEXT)
            continue;

        printLog();
    }

    pcap_close(pcap);  
    
    return 0;

}
int CAirodump::getWirelessPacket(pcap_t* pcap)
{


	struct pcap_pkthdr* header;
	int res = pcap_next_ex(pcap, &header, &packet);
	if (res == 0) NEXT;
	if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {
		printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
		return FAIL;
	}


    return SUCCESS;
	  

}

void CAirodump::convertPacket()
{
    ST_WIRELESS_PACKET* wirelessPacket = (ST_WIRELESS_PACKET*)packet;
   
    if(wirelessPacket->beaconFrame.frameControl != 0x80)
        return;    
    u_int8_t antennaSignal = 256 - wirelessPacket->ieee80211RadiotapHeader.antennaSignal;

    std::string bssid = getBSSID();
    std::string essid = getESSID();
    std::string pwr = std::to_string(-antennaSignal);
    
    std::vector<std::string> info;
    info.push_back(pwr); 
    info.push_back(essid);

    apInfo[bssid] = info;

}

void CAirodump::printLog()
{
    convertPacket();
    system("clear");
    std::cout << "BSSID\t\t\t" << "PWR                     " << "ESSID" <<std::endl;
    std::cout << std::endl;
    for(auto iter = apInfo.begin(); iter != apInfo.end(); iter++)
    {
        std::cout << iter->first << "\t" <<iter->second[0] << "\t\t\t" << iter->second[1] << std::endl;
    }

}

std::string CAirodump::getBSSID()
{
    ST_WIRELESS_PACKET* wirelessPacket = (ST_WIRELESS_PACKET*)packet;  
    char mac[31];
    sprintf(mac,"%02X:%02X:%02X:%02X:%02X:%02X",
            wirelessPacket->beaconFrame.bssid[0],
            wirelessPacket->beaconFrame.bssid[1],
            wirelessPacket->beaconFrame.bssid[2],
            wirelessPacket->beaconFrame.bssid[3],
            wirelessPacket->beaconFrame.bssid[4],
            wirelessPacket->beaconFrame.bssid[5]);

    return std::string(mac);
}

std::string CAirodump::getESSID()
{
    ST_WIRELESS_PACKET* wirelessPacket = (ST_WIRELESS_PACKET*)packet;  
    u_char* data = (u_char*)packet + 62;
    std::string essid;
    if(data[0] == '\0')
    {
        essid = "hidden AP";
        return essid;
    }

    for(int i = 0; 
        i < wirelessPacket->wirelessManager.tagLength;
        i++)
        essid += data[i];

    return essid;
  
}