#include "CAirodump.h"

CAirodump::CAirodump(char* dev)
{
    param.dev_ = dev;
	char errbuf[PCAP_ERRBUF_SIZE];
	pcap = pcap_open_live(param.dev_, BUFSIZ, 1, 1000, errbuf);
	if (pcap == NULL) {
		fprintf(stderr, "pcap_open_live(%s) return null - %s\n", param.dev_, errbuf);
        exit(1);
	}

}

CAirodump::~CAirodump(){

    pcap_close(pcap);  
}


int CAirodump::airodump()
{

    initscr();
    move(0,0);
  
    while(1)
    {
        int status = getWirelessPacket(pcap);
        if (status == FAIL)
            break; 
        if (status == NEXT)
            continue;
        
        convertPacket();
        printLog();
    }

    getch();

    
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

    std::string strPwr = std::to_string(-antennaSignal);
    std::string strBssid = getBSSID();
    std::string strEssid = getESSID();
    
    
    std::vector<std::string> info;
    info.push_back(strPwr); 
    info.push_back(strEssid);

    apInfo[strBssid] = info;

}

void CAirodump::printLog()
{
    clear();
    printw("BSSID\t\t\tPWR\t\t\tESSID\n");
    for(auto iter = apInfo.begin(); iter != apInfo.end(); iter++)
    {
        std::string strBssid = iter->first;
        std::string strEssid = iter->second[0];
        std::string strPwr = iter->second[1];

        printw("%s\t%s\t\t\t%s\n",strBssid.c_str(),strEssid.c_str(),strPwr.c_str());
        refresh();
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
    int essidPosition = sizeof(ST_WIRELESS_PACKET);
    ST_WIRELESS_PACKET* wirelessPacket = (ST_WIRELESS_PACKET*)packet;  
    u_char* data = (u_char*)packet + essidPosition;
    std::string strEssid;
    if(data[0] == '\0')
    {
        strEssid = "hidden AP";
        return strEssid;
    }

    for(int i = 0; 
        i < wirelessPacket->ssidParameter.tagLength;
        i++)
        strEssid += data[i];

    return strEssid;
  
}