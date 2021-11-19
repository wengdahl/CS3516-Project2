#include <iostream>
#include <stdio.h>
#include <pcap.h>
//#include <net/ethernet.h>
#include <netinet/ether.h>//contains ether_ntoa

uint32_t totalPackets = 0;
bool parseFirstPacket = true;
timeval startTime;
timeval elapsedTime;

//Callback - Process packet
void got_packet(u_char *empty, const struct pcap_pkthdr *header, const u_char *packet)
{
    if(parseFirstPacket) {
        startTime = header->ts;
        parseFirstPacket = false;
    }
    else {
        timeval currTime = header->ts;
        elapsedTime = {
            currTime.tv_sec - startTime.tv_sec,
            currTime.tv_usec - startTime.tv_usec
        };
        //If microseconds is negative, subtract one from seconds
        if(elapsedTime.tv_usec<0){
            elapsedTime.tv_sec -= 1;
            elapsedTime.tv_usec += 1000000;
        }
    }

    /*ether_header *ethernet = (ether_header*)packet;
    u_char *destAddr = ethernet->ether_dhost;
    std::cout << "Destination MAC: "<< destAddr << std::endl;//[0] << "." << destAddr[1] << "." << destAddr[2] << "." << destAddr[3] << std::endl;

    u_char *sourceAddr = ethernet->ether_shost;
    std::cout << "Source MAC: "<< sourceAddr[0] << "." << sourceAddr[1] << "." << sourceAddr[2] << "." << sourceAddr[3] << std::endl;
    */


    //Start new header code - got from http://yuba.stanford.edu/~casado/pcap/section2.html
    
    //Parse ethernet header
    struct ether_header * ethHeaderPntr = (struct ether_header *) packet;

    // Check packet type, can omit the prints later
    if (ntohs (ethHeaderPntr->ether_type) == ETHERTYPE_IP){
        std::cout << "Ethernet type hex: " << std::hex << ntohs(ethHeaderPntr->ether_type)<< " is an IPv4 packet"<< std::endl;
    }else  if (ntohs (ethHeaderPntr->ether_type) == ETHERTYPE_ARP){
        std::cout << "Ethernet type hex: " << std::hex << ntohs(ethHeaderPntr->ether_type)<< " is an ARP packet"<< std::endl;
    }else {
        std::cout << "Ethernet type hex: " << std::hex << ntohs(ethHeaderPntr->ether_type)<< " is not IPv4 or ARP packet"<< std::endl;
        exit(1);
    }

    //Print using ether_ntoa
    std::cout << " Destination Address:  " <<   ether_ntoa((struct ether_addr *)&ethHeaderPntr->ether_dhost) << std::endl;
    std::cout << " Source Address:  " <<        ether_ntoa((struct ether_addr *)&ethHeaderPntr->ether_shost) << std::endl;

    /// end new code

    totalPackets++;
    printf("Parsing packet\n");
}

int main(int argc, char *argv[])
{
        char *fname = argv[1];
        char *errbuf;
        pcap_t *handle;

        //Open offline, usinf argv as name of file to open
	    handle = pcap_open_offline(fname, errbuf);
        if (handle == NULL) {
            fprintf(stderr, "Couldn't open pcap file %s: %s\n", fname, errbuf);
            return(2);
        }

        //Check data is from ethernet
        int datalink = pcap_datalink(handle);
        if(datalink != 1){
            fprintf(stderr, "pcap not ethernet, return: %i\n", datalink);
            return(2);
        }

        int n = pcap_loop(handle, 0, got_packet, NULL);

        //Close pcap
        pcap_close(handle);

        //Print packet count
        std::cout << "Total Packets Parsed: " << totalPackets << std::endl;
        
        // Print packet capture timestamp
        tm *localTimeInfo = localtime(&startTime.tv_sec);
        std::cout << "Packet Capture Timestamp: " 
            << localTimeInfo->tm_mon + 1 << "/"
            << localTimeInfo->tm_mday << "/"
            << localTimeInfo->tm_year + 1900 << ", "
            << localTimeInfo->tm_hour << ":"
            << localTimeInfo->tm_min << ":"
            << localTimeInfo->tm_sec << ":"
            << startTime.tv_usec << std::endl;
        
        // Print elapsed time
        uint32_t duration = elapsedTime.tv_sec;
        std::cout << "Packet Capture Duration: " 
            << duration/3600 << ":"
            << (duration%3600)/60 << ":"
            << (duration%60) << ":"
            << elapsedTime.tv_usec << std::endl;

        return(0);
}