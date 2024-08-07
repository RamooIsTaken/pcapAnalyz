#ifndef SEARCHMAPWORKER_H
#define SEARCHMAPWORKER_H

#include <QObject>
#include <iostream>
#include <QMutex>
#include <unordered_map>
#include <chrono>
#include <pcap.h>
#include "packetstruct.h"


class SearchMapWorker : public QObject
{
    Q_OBJECT
public:
    SearchMapWorker(string fName);
    ~SearchMapWorker();
    void updateMap(const std::unordered_map<std::string, SessıonInfo>& newMap,
                   bool lastPacket,
                   const std::vector<std::vector<u_char>>& newPacket,
                   const std::vector<pcap_pkthdr>& newHeader);
    void controlMap();



signals:
    void finished();
private:
    std::unordered_map<std::string,int> written;
    std::unordered_map<std::string,SessıonInfo> sessionMap;

    std::vector<std::vector<u_char>> p;
    std::vector<pcap_pkthdr> h;

    std::time_t lastTakeData;
    std::chrono::time_point<std::chrono::high_resolution_clock> startChrono;

    bool isLastPacket;
    double start;
    double end;

    string defaultPath;


    QMutex m;
    string fileName;

    void printSessionInfo(std::string ses ,SessıonInfo sI);
    void printSesionExtracter(SessıonInfo sInfo);



};

#endif // SEARCHMAPWORKER_H
