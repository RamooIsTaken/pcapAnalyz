#ifndef PACKETOPERATION_H
#define PACKETOPERATION_H


#include <iostream>
#include <pcap.h>
#include <array>
#include <vector>
#include <string>
#include <unordered_map>
#include <chrono>

#include "packetstruct.h"
#include "SearchMapWorker.h"

struct SessionData {
    string sourceIp;
    string destIp;
    uint16_t sourcePort;
    uint16_t destPort;
    string protocol ;
    vector<int> index;
};


class packetOperation
{
public:
    packetOperation(const std::string& path);
    ~packetOperation();

    void packetCapture(int loopcount=0);
    void printPacketInfo();
    void printSessionMap();
    void printCsvFile();



protected:

private: //controlOpen(false),handle(nullptr),pCount(0)
    string filePath;
    string directory;
    string fileName;

    SearchMapWorker* searchMap;

    std::vector<std::vector<u_char>> packets;
    std::vector<pcap_pkthdr> headers;

    chrono::system_clock::time_point objStartTime;

    bool controlOpen;



    static void processPacket(void *user, const pcap_pkthdr *header, const u_char *pkt_data);  
    void createSessionMap(const PacketInfo& p);
    unordered_map<string,SessıonInfo> sessionMap;

    void splitPath(const string& str);



    //pcap veri yapıları
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;
    const u_char* packet;
    struct pcap_pkthdr header;



    string defaultPath ;
    string defaultTxtPath ;
    string defaultCsvPath ;


    int pCount;
    vector<PacketInfo> noStaticPackets;


    int streamIndex;


    void printSessionIndeks(); //bunlar kullanılmıyor kaldırılacak
    unordered_map<string,vector<string>> runTshark();
    unordered_map<string,vector<string>> sessionHash;
    void printSessionList();
    void findSessionList(const PacketInfo& pInfo,int cnt);

    unordered_map<int,SessionData> indexMap;


};

#endif // PACKETOPERATION_H
