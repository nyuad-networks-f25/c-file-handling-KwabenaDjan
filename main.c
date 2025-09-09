#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// PCAP file headers
typedef struct __attribute__((packed)) {
	uint32_t magic_number;
	uint16_t version_major;
	uint16_t version_minor;
	int32_t thiszone;
	uint32_t sigfigs;
	uint32_t snaplen;
	uint32_t network; // DLT_*
} pcap_file_header_t;

typedef struct __attribute__((packed)) {
	uint32_t ts_sec;
	uint32_t ts_usec;
	uint32_t incl_len; // number of octets of packet saved in file
	uint32_t orig_len; // actual length of packet when captured
} pcap_rec_header_t;

// Ethernet header
typedef struct __attribute__((packed)) {
	uint8_t dst[6];
	uint8_t src[6];
	uint16_t ethertype; // big endian
} eth_hdr_t;

// IPv4 header (without options)
typedef struct __attribute__((packed)) {
	uint8_t ver_ihl; // version(4) + IHL(4)
	uint8_t tos;
	uint16_t total_length;
	uint16_t identification;
	uint16_t flags_fragment;
	uint8_t ttl;
	uint8_t protocol;
	uint16_t hdr_checksum;
	uint32_t src_addr;
	uint32_t dst_addr;
} ipv4_hdr_t;

// UDP header
typedef struct __attribute__((packed)) {
	uint16_t src_port;
	uint16_t dst_port;
	uint16_t length;
	uint16_t checksum;
} udp_hdr_t;

int main() { return 0; }
