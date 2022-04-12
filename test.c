#include <pcap.h>

#include <stdbool.h>
#include <netinet/tcp.h>
#include <stdio.h>
#include <netinet/ip.h>
#include "sub.h"

void usage() {

    printf("syntax: pcap-test <interface>\n");

    printf("sample: pcap-test wlan0\n");

}



int main(int argc, char* argv[]) {

    if (argc != 2) {

        usage();

        return -1;

    }



    char* interface = argv[1];



    char errbuf[PCAP_ERRBUF_SIZE];

    pcap_t* pcap = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);

    if (pcap == NULL) {

        fprintf(stderr, "pcap_open_live(%s) return null - %s\n", interface, errbuf);

        return -1;

    }



    while (true) {

        struct pcap_pkthdr* header;
	struct libnet_ethernet_hdr* mac;
	struct ip* iph;
        const u_char* packet;

        int res = pcap_next_ex(pcap, &header, &packet);

        if (res == 0) continue;

        if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) {

            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));

            break;

        }
	mac = (struct libnet_ethernet_hdr *)packet;
	int i = 0;
	printf("src mac address -> ");
	while(i < ETHER_ADDR_LEN){
		printf("%02x:",mac->ether_shost[i]);
		if((i+1) == (ETHER_ADDR_LEN-1))
			printf("%02x",mac->ether_shost[++i]);
		i++;
	}
	printf("\n");
	printf("dst mac address -> ");
	i = 0;
        while(i < ETHER_ADDR_LEN){
		printf("%02x:",mac->ether_dhost[i]);
		if((i+1) == (ETHER_ADDR_LEN-1))
			printf("%02x",mac->ether_dhost[++i]);
		i++;
	}
	printf("\n");
	iph = (struct ip*)(packet+sizeof(struct libnet_ethernet_hdr));
	printf("src ip -> %s\n",inet_ntoa(iph->ip_src));
	printf("dst ip -> %s\n",inet_ntoa(iph->ip_dst));
	struct tcphdr* tcph;
	tcph = (struct tcphdr*)(packet + iph->ip_hl * 4);
	printf("src port -> %d\n", ntohs(tcph->source));
	printf("dst port -> %d\n", ntohs(tcph->dest));

	for(int i = 0; i < 8; i++)
	{
		printf("%02x",packet[i]);
	}
	printf("\n");
	printf("\n");
    }
}


