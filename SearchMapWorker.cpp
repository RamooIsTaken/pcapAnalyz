#include "SearchMapWorker.h"
#include "packetstruct.h"
#include <iostream>
#include <QMutexLocker>
#include <QThread>
#include <fstream>
#include <ctime>
#include <filesystem>
#include <chrono>

namespace fs = filesystem;


SearchMapWorker::SearchMapWorker(string fName) : fileName(fName) ,defaultPath("C:\\Users\\remzi\\Desktop\\tParse\\"),isLastPacket(false) {
    //this->start = std::stod()
    /*auto it = sessionMap.begin();
    this->start = std::stod(it->second.startTime);*/
    std::cout << "Search Map Worker Constructor " << std::endl;
    string mkCommand = "mkdir " + this->defaultPath + fileName ;

    this->startChrono = std::chrono::high_resolution_clock::now();

    /*int dirConrol = system(mkCommand.c_str());
    if (dirConrol==0){
        this->defaultPath += fileName + "\\";
    }*/

    fs::path dirPath = fs::path(defaultPath) / this->fileName;
    if(fs::create_directory(dirPath)){
        this->defaultPath = dirPath.string() + "\\";
    }else{
        std::cerr << "Failed to create directory: " << dirPath.string() << std::endl;
    }
}

SearchMapWorker::~SearchMapWorker(){
    this->written.clear();
    this->sessionMap.clear();
    this->h.clear();
    this->p.clear();
}



void SearchMapWorker::updateMap(const std::unordered_map<std::string, SessıonInfo>& newMap,
                                bool lastPacket,
                                const std::vector<std::vector<u_char>>& newPacket,
                                const std::vector<pcap_pkthdr>& newHeader){
    QMutexLocker locker(&m);
    this->sessionMap = newMap;
    this->h = newHeader;
    this->p = newPacket;
    this->lastTakeData = std::time(nullptr) ;
    this->isLastPacket = lastPacket;
    locker.unlock();
    //auto it = sessionMap.begin();
    //this->start = std::stod(it->second.startTime);
    //this->end = std::stod(it->second.endTime);
    //locker.unlock();
}




void SearchMapWorker::controlMap() {
    std::cout << "Control Map " << std::endl;
    while (true) {
        QThread::msleep(50000);
        this->m.lock();
        auto sIt = sessionMap.begin();
        while (sIt != sessionMap.end()) {
            SessıonInfo& sI = sIt->second;
            std::string key = sIt->first;
            if(sI.packetCount >= 32 || this->isLastPacket){
                auto cIt = written.find(key);
                if(cIt != written.end()){
                    if(cIt->second != sI.packetCount){
                        printSesionExtracter(sI);
                        written[key] = sI.packetCount;
                        sIt = sessionMap.erase(sIt);
                    }else{
                        sIt = sessionMap.erase(sIt);
                    }
                }else{
                    printSesionExtracter(sI);
                    written[key] = sI.packetCount;
                    sIt = sessionMap.erase(sIt);
                }
            }else{
                sIt++;
            }
        }

        this->m.unlock();
        if (sessionMap.empty()) {
            std::chrono::duration<double> processTime = std::chrono::high_resolution_clock::now() - this->startChrono;
            std::cout << this->fileName << " pcap dosyasinin session parse islemi "
                      << processTime.count() << " saniyede tamamlandi."
                      << "Toplam session sayisi : " << written.size() << std::endl;
            break;
        }
    }
    emit finished();
}



void SearchMapWorker::printSessionInfo(std::string key ,SessıonInfo sI){
    string txtName = this->defaultPath + key + ".txt";
    std::ofstream mapTxt(txtName);
    if(!mapTxt){
        cerr << "Dosya açılamadı " << endl;
        return;
    }

    mapTxt << "Source IP :" << sI.sourceIP << "\n"
           << "Destination IP :" << sI.destIP << "\n"
           << "Source Port :" << sI.sourcePort << "\n"
           << "Destination Port :" << sI.destPort << "\n"
           << "Stream Index :" << sI.streamIndex << "\n"
           << "Packets Count :" << sI.packetCount << "\n"
           << "Total Len :" << sI.packetsLen << "\n"
           << "Source To Destination :" << sI.sourceTodest << "\n"
           << "Source To Destination Length :" << sI.sourceTodestLen << "\n"
           <<"Destination To Source :" << sI.destToSource << "\n"
           <<"Destination To Source Length :" << sI.destToSourceLen << "\n"
           << "Start Time :" << sI.startTime << "\n"
           << "End Time :" << sI.endTime << "\n" << endl;
    mapTxt << "İndeks: " ;
        for(int indeks:sI.packetIndex){
        mapTxt << indeks << "-";
    }
    mapTxt.close();
}

void SearchMapWorker::printSesionExtracter(SessıonInfo sInfo){
    string pcapName = this->defaultPath + "session_" + std::to_string(sInfo.streamIndex) + ".pcap";

    pcap_dumper_t* d = pcap_dump_open(pcap_open_dead(DLT_EN10MB, 65535),pcapName.c_str());
    if(d == nullptr){
        std::cerr << "Pcap dosya hatası " << std::endl;
    }
    for(const auto& i : sInfo.packetIndex){
        const pcap_pkthdr& header = this->h[i-1];
        const std::vector<u_char>& packet = this->p[i-1];
        pcap_dump(reinterpret_cast<u_char*>(d),&header,packet.data());
    }
    pcap_dump_close(d);

}





/*void SearchMapWorker::controlMap(){
    std::cout << "Control Map " << std::endl;

    while(true){
        QThread::msleep(750);
        std::time_t subTms = std::time(nullptr)-this->lastTakeData ;
        QMutexLocker locker(&m);
        //std::cout << "Döngü numarası :" << subTms << "Map size : " << this->sessionMap.size() << endl ;
        auto sIt = sessionMap.begin();
        while(sIt!=sessionMap.end()){
            SessıonInfo& sI = sIt->second;
            std::string key = sIt->first;
            double sub = std::stod(sI.endTime) - std::stod(sI.startTime);

            if(sub>=0.3 || subTms >= 1.5){ //|| sub == 0
                auto cIt = written.find(key);
                if(cIt!=written.end()){
                    string c = cIt->second;
                    bool ctrl = (c ==  sI.startTime + "-" + sI.endTime);
                    if(!ctrl){
                        printSessionInfo(key,sI);
                        written[key] = sI.startTime + "-" + sI.endTime;
                        sIt = sessionMap.erase(sIt);
                    }else{
                        ++sIt;
                    }
                }else{
                    printSessionInfo(key,sI);
                    written[key] = sI.startTime + "-" + sI.endTime;
                    sIt = sessionMap.erase(sIt);
                }
            }else{
                ++sIt;
            }
        }

        locker.unlock();
        if(sessionMap.empty()){
            std::cout << this->fileName << " pcap dosyasinin session parse islemi "
                      << std::time(nullptr)-this->startTms << " saniyede tamamlandi." <<
                        "Toplam session sayisi : " << written.size() << std::endl;
            break;
        }

    }
    emit finished();
}*/
