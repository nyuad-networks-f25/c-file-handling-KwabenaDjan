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

static int read_fully(FILE *fp, void *buf, size_t sz) {
	return fread(buf, 1, sz, fp) == sz ? 0 : -1;
}

// static int is_printable_ascii(uint8_t c) {
// 	return (c >= 32 && c <= 126) || c == '\n' || c == '\r' || c == '\t';
// }

static inline uint32_t swap32(uint32_t v) {
	return ((v & 0x000000FFu) << 24) | ((v & 0x0000FF00u) << 8) |
	       ((v & 0x00FF0000u) >> 8) | ((v & 0xFF000000u) >> 24);
}

int main(int argc, char **argv) {
	if (argc < 2) {
		fprintf(stderr, "Error: no PCAP file specified. Usage: %s <pcap_file>\n", argv[0]);
		return 1;
	}

	const char *pcap_path = argv[1];
	FILE *fp = fopen(pcap_path, "rb");
	if (!fp) {
		fprintf(stderr, "Error: failed to open '%s': %s\n", pcap_path, strerror(errno));
		return 1;
	}

	pcap_file_header_t fh;
	if (read_fully(fp, &fh, sizeof(fh)) != 0) {
		fprintf(stderr, "Error: failed to read PCAP global header.\n");
		fclose(fp);
		return 1;
	}

	// Detect endianness via magic number
	uint32_t magic = fh.magic_number;
	int swapped = 0;
	if (magic == 0xa1b2c3d4u) {
		// native big endian in file; on little-endian hosts we need ntohl semantics below when parsing per-packet lengths
		swapped = 0;
	} else if (magic == 0xd4c3b2a1u) {
		// byte-swapped
		swapped = 1;
	} else {
		// also allow nanosecond-resolution magic numbers
		if (magic == 0xa1b23c4du) {
			swapped = 0;
		} else if (magic == 0x4d3cb2a1u) {
			swapped = 1;
		} else {
			fprintf(stderr, "Error: unsupported PCAP magic number.\n");
			fclose(fp);
			return 1;
		}

	}

    	// Iterate packets
	for (;;) {
		pcap_rec_header_t rh;
		if (read_fully(fp, &rh, sizeof(rh)) != 0) {
			break; // EOF
		}
		uint32_t incl_len = swapped ? swap32(rh.incl_len) : rh.incl_len;
		if (incl_len == 0) {
			continue;
		}
		uint8_t *packet = (uint8_t *)malloc(incl_len);
		if (!packet) {
			fprintf(stderr, "Error: out of memory.\n");
			fclose(fp);
			return 1;
		}
		if (read_fully(fp, packet, incl_len) != 0) {
			free(packet);
			fprintf(stderr, "Error: truncated packet data.\n");
			fclose(fp);
			return 1;
		}

        // Parse Ethernet
		if (incl_len < sizeof(eth_hdr_t)) {
			free(packet);
			continue;
		}
		eth_hdr_t *eth = (eth_hdr_t *)packet;
		uint16_t ethertype = ntohs(eth->ethertype);
		size_t offset = sizeof(eth_hdr_t);
		if (ethertype == 0x8100 && incl_len >= offset + 4) {
			// 802.1Q VLAN tag present: skip 4 bytes and read real ethertype
			offset += 4;
			ethertype = ntohs(*(uint16_t *)(packet + offset - 2));
		}
		if (ethertype != 0x0800) { // IPv4 only
			free(packet);
			continue;
		}

        // Parse IPv4
		if (incl_len < offset + sizeof(ipv4_hdr_t)) {
			free(packet);
			continue;
		}
		ipv4_hdr_t *ip = (ipv4_hdr_t *)(packet + offset);
		uint8_t ihl = (ip->ver_ihl & 0x0F) * 4;
		if (incl_len < offset + ihl) {
			free(packet);
			continue;
		}
		if (ip->protocol != 17) { // UDP
			free(packet);
			continue;
		}
		offset += ihl;

       // Parse UDP
		if (incl_len < offset + sizeof(udp_hdr_t)) {
			free(packet);
			continue;
		}
		udp_hdr_t *udp = (udp_hdr_t *)(packet + offset);
		uint16_t src_port = ntohs(udp->src_port);
		uint16_t dst_port = ntohs(udp->dst_port);
		uint16_t udp_len = ntohs(udp->length);
		uint16_t checksum = ntohs(udp->checksum);

		printf("Src Port: %u\n", (unsigned)src_port);
		printf("Dst Port: %u\n", (unsigned)dst_port);
		printf("Length: %u\n", (unsigned)udp_len);
		printf("Checksum: 0x%04x\n", (unsigned)checksum);
 
}
}
