#include "pkt.h"

uint16_t Cal_chksum(const u_char *data, uint16_t base, uint16_t len)
{
	uint32_t sum = (uint32_t)base;
	for(int i = 0; i < len / 2; i++)
	{
		sum += (uint32_t)(*(uint16_t*)(data + i * 2));
	}

	if(len % 2)
	{
		uint32_t tmp = (uint32_t)(*(uint8_t*)(data + len - 1));
		sum += tmp;
	}
	
	sum = (sum >> 16) + (sum & 0xFFFF);
	sum = (sum >> 16) + (sum & 0xFFFF);

	return (sum & 0xFFFF) ^ 0xFFFF;
}

uint16_t Check_pkt(const u_char *pkt, string block)
{
	Eth_hdr *eth_hdr = (Eth_hdr*)pkt;
	if(eth_hdr->eth_type != htons(ETHERTYPE_IP))
	{
		cout << "not IP\n";
		return 0;
	}
		
	IP_hdr *ip_hdr = (IP_hdr*)(pkt + ETHERHDR_LEN);
	if(ip_hdr->prot != PROTOCOL_TCP)
	{
		cout << "not TCP\n";
		return 0;
	}

	TCP_hdr *tcp_hdr = (TCP_hdr*)(pkt + ETHERHDR_LEN + ip_hdr->hdr_len * 4);
	uint16_t tcp_data_len = ip_hdr->len - (ip_hdr->hdr_len + tcp_hdr->hdr_len) * 4;
	if(tcp_data_len == 0)
	{
		cout << "no TCP data\n";
		return 0;
	}

	string tcp_data = string((const char*)(pkt + ETHERHDR_LEN + 
					       ip_hdr->hdr_len * 4 + 
					       tcp_hdr->hdr_len * 4), tcp_data_len);

	if(tcp_data.substr(0, 3) != "GET" &&
    	   tcp_data.substr(0, 3) != "PUT" &&
      	   tcp_data.substr(0, 4) != "POST" &&
      	   tcp_data.substr(0, 4) != "HEAD" &&
      	   tcp_data.substr(0, 6) != "DELETE" &&
     	   tcp_data.substr(0, 6) != "OPTION")
	{
		cout << "no HTTP method\n";
		return 0;
	}
	
	size_t pos = tcp_data.find("Host: ");
	if(pos == string::npos)
	{
		cout << "no \"Host: \" found\n";
		return 0;
	}
	
	string host = tcp_data.substr(pos + 6);
	pos = host.find("\r\n");
	host = host.substr(0, pos);
	cout << "HTTP host : " << host << '\n';

	if(host == block)
		return tcp_data_len;

	return 0;
}

uint32_t Forward(const u_char *recv_pkt, const u_char *send_pkt, bool flag)
{

	const u_char msg[10] = "bye bye!";
	
	Eth_hdr *recv_eth_hdr = (Eth_hdr*)recv_pkt;
	IP_hdr 	*recv_ip_hdr  = (IP_hdr*)(recv_pkt + ETHERHDR_LEN);
	TCP_hdr *recv_tcp_hdr = (TCP_hdr*)(recv_pkt + ETHERHDR_LEN + recv_ip_hdr->hdr_len * 4);
	uint16_t tcp_data_len = ntohs(recv_ip_hdr->len) - (recv_ip_hdr->hdr_len + recv_tcp_hdr->hdr_len) * 4;

	Eth_hdr *send_eth_hdr = (Eth_hdr*)send_pkt;
	*send_eth_hdr = *recv_eth_hdr;

	IP_hdr  *send_ip_hdr  = (IP_hdr*)(send_pkt + ETHERHDR_LEN);
	*send_ip_hdr = *recv_ip_hdr;

	TCP_hdr *send_tcp_hdr = (TCP_hdr*)(send_pkt + ETHERHDR_LEN + send_ip_hdr->hdr_len * 4);
	*send_tcp_hdr = *recv_tcp_hdr;
	send_tcp_hdr->hdr_len = 5;
	send_tcp_hdr->seq_num = htonl(ntohl(recv_tcp_hdr->seq_num) + (uint32_t)tcp_data_len);
	send_tcp_hdr->chksum = 0;
	send_tcp_hdr->urg = 0;
	send_tcp_hdr->ack = 1;
	send_tcp_hdr->psh = 0;
	send_tcp_hdr->rst = 0;
	send_tcp_hdr->syn = 0;
	send_tcp_hdr->fin = 0;
	if(flag)	send_tcp_hdr->fin = 1;
	else 		send_tcp_hdr->rst = 1;

	Pseudo_hdr p_hdr;
	p_hdr.src_ip = send_ip_hdr->src_ip;
	p_hdr.dst_ip = send_ip_hdr->dst_ip;
	p_hdr.rsv = 0;
	p_hdr.prot = PROTOCOL_TCP;
	p_hdr.len = tcp_data_len;

	uint16_t chksum = Cal_chksum((const u_char*)&p_hdr, 0, sizeof(p_hdr));
	send_tcp_hdr->chksum = htons(Cal_chksum((const u_char*)&send_tcp_hdr, chksum, 
					 	send_tcp_hdr->hdr_len * 4));
	
	send_ip_hdr->len = htons((send_ip_hdr->hdr_len + send_tcp_hdr->hdr_len) * 4);
	send_ip_hdr->chksum = htons(Cal_chksum((const u_char*)&send_ip_hdr, 0, send_ip_hdr->hdr_len));

	if(flag)
	{
		const u_char *tcp_data = (const u_char*)(send_pkt + ETHERHDR_LEN + 
							 send_ip_hdr->hdr_len * 4 + 
							 send_tcp_hdr->hdr_len * 4);
		memcpy((void*)tcp_data, (const void*)msg, MSG_LEN);
		return ETHERHDR_LEN + send_ip_hdr->hdr_len * 4 + send_tcp_hdr->hdr_len * 4 + MSG_LEN;
	}
	
	return ETHERHDR_LEN + send_ip_hdr->hdr_len * 4 + send_tcp_hdr->hdr_len * 4;
}

uint32_t Backward(const u_char *recv_pkt, const u_char *send_pkt, bool flag)
{

	const u_char msg[10] = "bye bye!";
	
	Eth_hdr *recv_eth_hdr = (Eth_hdr*)recv_pkt;
	IP_hdr 	*recv_ip_hdr  = (IP_hdr*)(recv_pkt + ETHERHDR_LEN);
	TCP_hdr *recv_tcp_hdr = (TCP_hdr*)(recv_pkt + ETHERHDR_LEN + recv_ip_hdr->hdr_len * 4);
	uint16_t tcp_data_len = ntohs(recv_ip_hdr->len) - (recv_ip_hdr->hdr_len + recv_tcp_hdr->hdr_len) * 4;

	Eth_hdr *send_eth_hdr = (Eth_hdr*)send_pkt;
	*send_eth_hdr = *recv_eth_hdr;
	for(int i = 0; i < 6; i++)
	{
		send_eth_hdr->dst_mac[i] = recv_eth_hdr->src_mac[i];
		send_eth_hdr->src_mac[i] = recv_eth_hdr->dst_mac[i];
	}

	IP_hdr  *send_ip_hdr  = (IP_hdr*)(send_pkt + ETHERHDR_LEN);
	*send_ip_hdr = *recv_ip_hdr;
	send_ip_hdr->src_ip = recv_ip_hdr->dst_ip;
	send_ip_hdr->dst_ip = recv_ip_hdr->src_ip;

	TCP_hdr *send_tcp_hdr = (TCP_hdr*)(send_pkt + ETHERHDR_LEN + send_ip_hdr->hdr_len * 4);
	*send_tcp_hdr = *recv_tcp_hdr;
	send_tcp_hdr->src_port = recv_tcp_hdr->dst_port;
	send_tcp_hdr->dst_port = recv_tcp_hdr->src_port;
	send_tcp_hdr->hdr_len = 5;
	send_tcp_hdr->seq_num = recv_tcp_hdr->ack_num;
	send_tcp_hdr->ack_num = htonl(ntohl(recv_tcp_hdr->seq_num) + (uint32_t)tcp_data_len);
	send_tcp_hdr->chksum = 0;
	send_tcp_hdr->urg = 0;
	send_tcp_hdr->ack = 1;
	send_tcp_hdr->psh = 0;
	send_tcp_hdr->rst = 0;
	send_tcp_hdr->syn = 0;
	send_tcp_hdr->fin = 0;
	if(flag)	send_tcp_hdr->fin = 1;
	else 		send_tcp_hdr->rst = 1;

	Pseudo_hdr p_hdr;
	p_hdr.src_ip = send_ip_hdr->src_ip;
	p_hdr.dst_ip = send_ip_hdr->dst_ip;
	p_hdr.rsv = 0;
	p_hdr.prot = PROTOCOL_TCP;
	p_hdr.len = tcp_data_len;

	uint16_t chksum = Cal_chksum((const u_char*)&p_hdr, 0, sizeof(p_hdr));
	send_tcp_hdr->chksum = htons(Cal_chksum((const u_char*)&send_tcp_hdr, chksum, 
					  	 send_tcp_hdr->hdr_len * 4));

	send_ip_hdr->len = htons((send_ip_hdr->hdr_len + send_tcp_hdr->hdr_len) * 4);
	send_ip_hdr->chksum = htons(Cal_chksum((const u_char*)&send_ip_hdr, 0, send_ip_hdr->hdr_len));

	if(flag)
	{
		const u_char *tcp_data = (const u_char*)(send_pkt + ETHERHDR_LEN + 
							 send_ip_hdr->hdr_len * 4 + 
							 send_tcp_hdr->hdr_len * 4);
		memcpy((void*)tcp_data, (const void*)msg, MSG_LEN);
		return ETHERHDR_LEN + send_ip_hdr->hdr_len * 4 + send_tcp_hdr->hdr_len * 4 + MSG_LEN;
	}
	
	return ETHERHDR_LEN + send_ip_hdr->hdr_len * 4 + send_tcp_hdr->hdr_len * 4;
}



