#include <iostream>
#include <string> 
#include <vector>
#include <map>
#include <utility>
#include <unistd.h>
#include <stdio.h>
#include <pcap.h>

enum status
{
    SUCCESS,
    FAIL,
    NEXT

};

struct Param {
	char* dev_;
};

struct ST_IEEE80211_RADIOTAP_HEADER 
{
    u_int8_t        version;     
    u_int8_t        pad;
    u_int16_t       len;         
    u_int32_t       fpresent;
	u_int32_t       bpresent;  
	u_int8_t		flags;
	u_int8_t		dataRate;
	u_int16_t		channelFrequency;
	u_int16_t		channelFlags;  
	u_int8_t		antennaSignal; //PWR
	u_int8_t		antenna;
	u_int16_t		rxFlags; 
	u_int8_t		antennaSignalT;
	u_int8_t		antennaT;
};

struct ST_BEACON_FRAME
{
	u_int16_t frameControl; //0x0008
	u_int16_t duration;
	u_int8_t destinationAddr[6];
	u_int8_t sourceAddr[6];
	u_int8_t bssid[6];
	u_int16_t seqNum;
};

struct ST_WIRELESS_MANAGER
{
	u_int64_t timestamp;
	u_int16_t beaconInterval;
	u_int16_t capabilityInfo;
	u_int8_t tagName;
	u_int8_t tagLength;
};

struct ST_WIRELESS_PACKET
{
	ST_IEEE80211_RADIOTAP_HEADER ieee80211RadiotapHeader;
	ST_BEACON_FRAME beaconFrame;
	ST_WIRELESS_MANAGER wirelessManager;
};



class CAirodump 
{
private:
	
    Param param;
    const u_char* packet;
    std::map<std::string,std::vector<std::string>> apInfo; 

public:

    CAirodump();
    ~CAirodump();
    int airodump(char * dev);

private:

    int getWirelessPacket(pcap_t* pcap);
    void convertPacket();
	void printLog();
	std::string getESSID();
	std::string getBSSID();
};