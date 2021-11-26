#include <iostream>
#include <stdio.h>
#include <pcap.h>
#include <net/ethernet.h>
#include <netinet/ether.h>//contains ether_ntoa
#include <netinet/ip.h> //IP header
#include <netinet/udp.h> //UDP header
#include <net/if_arp.h> //ARP header

uint32_t totalPackets = 0;
timeval startTime;
timeval elapsedTime;

struct PacketStruct {
    bool firstPacket = true;
    int min;
    int max;
    int total;
    int count;
};

/*struct ether_arp {
  unsigned short arp_hrd;
  unsigned short arp_pro;
  unsigned char arp_hln;
  unsigned char arp_pln;
  unsigned short arp_op;
  unsigned char arp_sha[6];
  unsigned char arp_spa[4];
  unsigned char arp_tha[6];
  unsigned char arp_tpa[4];
};*/

//Callback - Process packet
void got_packet(u_char *structPointer, const struct pcap_pkthdr *header, const u_char *packet)
{
    //Cast packetstruct for later use
    PacketStruct *PacketInfoStruct =  (PacketStruct *)structPointer;

    //Packet
    if(PacketInfoStruct->firstPacket) {
        startTime = header->ts;
        PacketInfoStruct->firstPacket = false;
        PacketInfoStruct->min = header->len;
        PacketInfoStruct->max = header->len;
        PacketInfoStruct->total = header->len;
        PacketInfoStruct->count = 1;
    }
    else {
        //Length Statistics
        if(PacketInfoStruct->min > header->len)
            PacketInfoStruct->min = header->len;
        if(PacketInfoStruct->max < header->len)
            PacketInfoStruct->max = header->len;
        PacketInfoStruct->total += header->len;
        PacketInfoStruct->count++;
        
        //Time info
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


    //Start new header code - got from http://yuba.stanford.edu/~casado/pcap/section2.html
    
    //Parse ethernet header
    struct ether_header * ethHeaderPntr = (struct ether_header *) packet;


    /// end new code

    totalPackets++;
    printf("Parsing packet\n");


    // Check packet type, can omit the prints later
    if (ntohs (ethHeaderPntr->ether_type) == ETHERTYPE_IP){
        std::cout << "Ethernet type hex: " << std::hex << ntohs(ethHeaderPntr->ether_type)<< " is an IPv4 packet"<< std::endl;

        //Print using ether_ntoa - I think we are supposed to ignore MAC address form ether header for ARP, ARP header contaisn that information, and it could be "broadcast" address for ARP
        std::cout << "Destination MAC Address: " <<   ether_ntoa((struct ether_addr *)&ethHeaderPntr->ether_dhost) << std::endl;
        std::cout << "Source MAC Address: " <<        ether_ntoa((struct ether_addr *)&ethHeaderPntr->ether_shost) << std::endl;

        iphdr *ip_header = (struct iphdr *) (packet + ETH_HLEN);

        char sourceAddr[INET_ADDRSTRLEN];
        char destAddr[INET_ADDRSTRLEN];
        //Convert from number to dotted decimal
        inet_ntop( AF_INET, &ip_header->saddr, sourceAddr, INET_ADDRSTRLEN);
        inet_ntop( AF_INET, &ip_header->daddr, destAddr, INET_ADDRSTRLEN);

        std::cout << std::dec << "Source IP Address: " << sourceAddr << std::endl;
        std::cout << "Destination IP address: " << destAddr<< std::endl;

        //Check UDP - Protocol 17 is UDP, anything else is ignored
        if(static_cast<unsigned>(ip_header->protocol) == 17){
            //IP header length = 32* IHL (internet header length) bits = 4*IHL bytes
            udphdr *udp_header = (struct udphdr *) (packet + ETH_HLEN + 4*static_cast<unsigned>(ip_header->ihl));
            
            //Print UDP ports
            std::cout << std::dec << "Source Port: " << ntohs(udp_header->uh_sport) << std::endl;
            std::cout << "Destination Port: " <<  ntohs(udp_header->uh_dport) << std::endl;
        }

        //tot_len
    }else  if (ntohs (ethHeaderPntr->ether_type) == ETHERTYPE_ARP){
        std::cout << "Ethernet type hex: " << std::hex << ntohs(ethHeaderPntr->ether_type)<< " is an ARP packet"<< std::endl;

        ether_arp *arp_header_pntr = (struct ether_arp *) (packet + ETH_HLEN);

        //Both IP addresses known
        char sourceAddr[INET_ADDRSTRLEN];
        char destAddr[INET_ADDRSTRLEN];
        //Convert from number to dotted decimal
        inet_ntop( AF_INET, &arp_header_pntr->arp_spa, sourceAddr, INET_ADDRSTRLEN);
        inet_ntop( AF_INET, &arp_header_pntr->arp_tpa, destAddr, INET_ADDRSTRLEN);

        std::cout << std::dec << "Source IP Address: " << sourceAddr << std::endl;
        std::cout << "Destination IP address: " << destAddr<< std::endl;

        if(ntohs(arp_header_pntr->arp_op) == 1){
            std::cout << std::dec << "ARP Request" << std::endl;

            //Print using ether_ntoa - I think we are supposed to ignore MAC address form ether header for ARP, ARP header contaisn that information, and it could be "broadcast" address for ARP
            std::cout << "Source MAC Address: " <<   ether_ntoa((struct ether_addr *)&arp_header_pntr->arp_sha) << std::endl;
            std::cout << "Destination MAC Address: " << "Unknown" << std::endl; // Not porvided in ARP request

        }else{
            std::cout << std::dec << "ARP Reply"<< std::endl;
            //Print using ether_ntoa - I think we are supposed to ignore MAC address form ether header for ARP, ARP header contaisn that information, and it could be "broadcast" address for ARP
            std::cout << "Source MAC Address: " <<   ether_ntoa((struct ether_addr *)&arp_header_pntr->arp_sha) << std::endl;
            std::cout << "Destination MAC Address: " <<        ether_ntoa((struct ether_addr *)&arp_header_pntr->arp_tha) << std::endl;
        }


    }else {
        std::cout << "Ethernet type hex: " << std::hex << ntohs(ethHeaderPntr->ether_type)<< " is not IPv4 or ARP packet"<< std::endl;
    }

    //Print empty line between packets
    std::cout << std::endl;
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


        PacketStruct packetData;
        int n = pcap_loop(handle, 0, got_packet, (u_char*)&packetData);

        //Close pcap
        pcap_close(handle);

        //Print packet count
        std::cout << "Total Packets Parsed: " << std::dec << totalPackets << std::endl;
        
        // Print packet capture timestamp
        tm *localTimeInfo = localtime(&startTime.tv_sec);
        std::cout << std::dec <<"Packet Capture Timestamp: " 
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

        //Print total number of packets
        std::cout << "Total number of packets: " << packetData.count << std::endl;

        /*
        • Create two lists, one for unique senders and one for unique recipients, along with the total number
        of packets associated with each. This should be done at two layers: Ethernet and IP. For Ethernet,
        represent the addresses in hex-colon notation. For IP addresses, use the standard dotted decimal
        notation.
        • Create a list of machines participating in ARP, including their associated MAC addresses and, where
        possible, the associated IP addresses.
        • For UDP, create two lists for the unique ports seen: one for the source ports and one for the destination
        ports.
        */

       //Report the average, minimum, and maximum packet sizes. The packet size refers to everything beyond the tcpdump header
       std::cout << "Packet minimum size: " << packetData.min
            << ", Packet maximum size: " << packetData.max
            << ", Packet average (mean) size: " << (packetData.total/packetData.count) << std::endl;

        return(0);
}