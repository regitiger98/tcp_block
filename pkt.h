#pragma once

#include<pcap.h>
#include<stdio.h>
#include<stdint.h>
#include<arpa/inet.h>
#include<string.h>

#include<iostream>
#include<string>

using namespace std;

#define ETHERHDR_LEN	14
#define ETHERTYPE_IP	0x0800
#define PROTOCOL_TCP	0x06
#define MSG_LEN 	8

struct Eth_hdr
{
	uint8_t	dst_mac[6];
	uint8_t	src_mac[6];
	uint16_t eth_type;
};

struct IP_hdr
{
	uint8_t hdr_len	:4;
	uint8_t ver	:4;
	uint8_t tos;
	uint16_t len;
	uint16_t id;
	uint16_t offset	:13;
	uint16_t flag	:3;
	uint8_t ttl;
	uint8_t prot;
	uint16_t chksum;
	uint32_t src_ip;
	uint32_t dst_ip;
};

struct TCP_hdr
{
	uint16_t src_port;
	uint16_t dst_port;
	uint32_t seq_num;
	uint32_t ack_num;
	uint8_t rsv1	:4;
	uint8_t hdr_len	:4;
	uint8_t fin	:1;
	uint8_t syn	:1;
	uint8_t rst	:1;
	uint8_t psh	:1;
	uint8_t ack	:1;
	uint8_t urg	:1;
	uint8_t rsv2	:2;
	uint16_t win_size;
	uint16_t chksum;
	uint16_t urg_ptr;
};

struct Pseudo_hdr
{
	uint32_t src_ip;
	uint32_t dst_ip;
	uint8_t rsv;
	uint8_t prot;
	uint16_t len;
};

uint16_t Cal_chksum(const u_char *data, uint16_t base, uint16_t len);

uint16_t Check_pkt(const u_char *pkt, string block);

uint32_t Forward(const u_char *recv_pkt, const u_char *send_pkt, bool flag);

uint32_t Backward(const u_char *recv_pkt, const u_char *send_pkt, bool flag);
