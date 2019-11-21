#include "pkt.h"

void usage() {
	cout << "syntax: tcp_block <interface> <host>\n";
	cout << "sample: tcp_block wlan0 test.gilgil.net\n";
}

int main(int argc, char* argv[]) {
	if (argc != 3) {
		usage();
		return -1;
	}

  	char *interface = argv[1];
	string host = string((const char*)argv[2], strlen(argv[2]));
  	char errbuf[PCAP_ERRBUF_SIZE];
  	pcap_t *handle = pcap_open_live(interface, BUFSIZ, 1, 1000, errbuf);
  	if (handle == NULL) 
	{
		fprintf(stderr, "couldn't open device %s: %s\n", interface, errbuf);
		return -1;
  	}

  	while (true) {
		struct pcap_pkthdr *header;
		const u_char *pkt;
		int res = pcap_next_ex(handle, &header, &pkt);
		if (res == 0) continue;
		if (res == -1 || res == -2) break;

		//cout << "-------------------------------------------\n";
		//cout << "[+] " << header->caplen << " bytes captured\n";		

		uint16_t tcp_data_len = Check_pkt(pkt, host);
		if(tcp_data_len == 0) continue;
		cout << "Packet Blocked\n";

		const u_char *bw_pkt = (const u_char*)malloc(100);
		uint32_t bw_len = Backward(pkt, bw_pkt, 0);
		pcap_sendpacket(handle, bw_pkt, bw_len);


		const u_char *fw_pkt = (const u_char*)malloc(100);
		uint32_t fw_len = Forward(pkt, fw_pkt, 0);
		pcap_sendpacket(handle, fw_pkt, fw_len);
		
		free((void*)bw_pkt);
		free((void*)fw_pkt);
 	}

 	pcap_close(handle);
 	return 0;
}
