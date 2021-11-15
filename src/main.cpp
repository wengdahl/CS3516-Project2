#include <stdio.h>
#include <pcap.h>


//Callback - Process packet
void got_packet(u_char *empty, const struct pcap_pkthdr *header, const u_char *packet)
{
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

        //Print packet information
        printf("Parsing complete: %i\n",n);

        return(0);
}
