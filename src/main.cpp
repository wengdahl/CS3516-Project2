#include <iostream>
#include <stdio.h>
#include <pcap.h>
#include <net/ethernet.h>

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

    // ether_header *ethernet = (ether_header*)packet;
    // uint8_t *destAddr = ethernet->ether_dhost;
    // std::cout << destAddr[0] << "." << destAddr[1] << "." << destAddr[2] << "." << destAddr[3] << std::endl;

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