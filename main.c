#include <arpa/inet.h>
#include <errno.h>
#include <netinet/in.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

// PCAP file headers
typedef struct __attribute__((packed)) {
    uint32_t magic_number;      // Magic number to identify PCAP format and endianness
    uint16_t version_major;     // Major version number
    uint16_t version_minor;     // Minor version number
    int32_t thiszone;           // GMT to local correction
    uint32_t sigfigs;           // Accuracy of timestamps
    uint32_t snaplen;           // Max length of captured packets, in octets
    uint32_t network;           // Data link type (DLT_*)
} pcap_file_header_t;

typedef struct __attribute__((packed)) {
    uint32_t ts_sec;            // Timestamp seconds
    uint32_t ts_usec;           // Timestamp microseconds
    uint32_t incl_len;          // Number of octets of packet saved in file
    uint32_t orig_len;          // Actual length of packet when captured
} pcap_rec_header_t;

// Ethernet header
typedef struct __attribute__((packed)) {
    uint8_t dst[6];             // Destination MAC address
    uint8_t src[6];             // Source MAC address
    uint16_t ethertype;         // Protocol type (big endian)
} eth_hdr_t;

// IPv4 header (without options)
typedef struct __attribute__((packed)) {
    uint8_t ver_ihl;            // Version (4 bits) + Internet Header Length (4 bits)
    uint8_t tos;                // Type of service
    uint16_t total_length;      // Total length of the IP packet
    uint16_t identification;    // Identification
    uint16_t flags_fragment;    // Flags + Fragment offset
    uint8_t ttl;                // Time to live
    uint8_t protocol;           // Protocol (e.g., UDP, TCP)
    uint16_t hdr_checksum;      // Header checksum
    uint32_t src_addr;          // Source IP address
    uint32_t dst_addr;          // Destination IP address
} ipv4_hdr_t;

// UDP header
typedef struct __attribute__((packed)) {
    uint16_t src_port;          // Source port
    uint16_t dst_port;          // Destination port
    uint16_t length;            // Length of UDP packet (header + data)
    uint16_t checksum;          // UDP checksum
} udp_hdr_t;

// Reads 'sz' bytes from file 'fp' into buffer 'buf'. Returns 0 on success, -1 on failure.
static int read_fully(FILE *fp, void *buf, size_t sz) {
    return fread(buf, 1, sz, fp) == sz ? 0 : -1;
}

// Checks if a byte is printable ASCII or whitespace (newline, carriage return, tab)
static int is_printable_ascii(uint8_t c) {
    return (c >= 32 && c <= 126) || c == '\n' || c == '\r' || c == '\t';
}

// Swaps the byte order of a 32-bit integer (used for endianness conversion)
static inline uint32_t swap32(uint32_t v) {
    return ((v & 0x000000FFu) << 24) | ((v & 0x0000FF00u) << 8) |
           ((v & 0x00FF0000u) >> 8) | ((v & 0xFF000000u) >> 24);
}

int main(int argc, char **argv) {
    // Check for correct usage: program expects a PCAP file as argument
    if (argc < 2) {
        fprintf(stderr, "Error: no PCAP file specified. Usage: %s <pcap_file>\n", argv[0]);
        return 1;
    }

    const char *pcap_path = argv[1]; // Path to the PCAP file
    FILE *fp = fopen(pcap_path, "rb"); // Open PCAP file for reading in binary mode
    if (!fp) {
        fprintf(stderr, "Error: failed to open '%s': %s\n", pcap_path, strerror(errno));
        return 1;
    }

    pcap_file_header_t fh;
    // Read the global PCAP header
    if (read_fully(fp, &fh, sizeof(fh)) != 0) {
        fprintf(stderr, "Error: failed to read PCAP global header.\n");
        fclose(fp);
        return 1;
    }

    // Detect endianness via magic number in the PCAP header
    uint32_t magic = fh.magic_number;
    int swapped = 0; // Flag to indicate if byte swapping is needed
    if (magic == 0xa1b2c3d4u) {
        // Native big endian in file; no swapping needed
        swapped = 0;
    } else if (magic == 0xd4c3b2a1u) {
        // Byte-swapped (little endian); swapping needed
        swapped = 1;
    } else {
        // Also allow nanosecond-resolution magic numbers
        if (magic == 0xa1b23c4du) {
            swapped = 0;
        } else if (magic == 0x4d3cb2a1u) {
            swapped = 1;
        } else {
            // Unsupported PCAP format
            fprintf(stderr, "Error: unsupported PCAP magic number.\n");
            fclose(fp);
            return 1;
        }
    }

    // Iterate over packets in the PCAP file
    for (;;) {
        pcap_rec_header_t rh;
        // Read the per-packet header
        if (read_fully(fp, &rh, sizeof(rh)) != 0) {
            break; // EOF or error
        }
        // Get the length of the packet data, swapping bytes if needed
        uint32_t incl_len = swapped ? swap32(rh.incl_len) : rh.incl_len;
        if (incl_len == 0) {
            continue; // Skip empty packets
        }
        // Allocate memory for the packet data
        uint8_t *packet = (uint8_t *)malloc(incl_len);
        if (!packet) {
            fprintf(stderr, "Error: out of memory.\n");
            fclose(fp);
            return 1;
        }
        // Read the packet data
        if (read_fully(fp, packet, incl_len) != 0) {
            free(packet);
            fprintf(stderr, "Error: truncated packet data.\n");
            fclose(fp);
            return 1;
        }

        // Parse Ethernet header
        if (incl_len < sizeof(eth_hdr_t)) {
            free(packet);
            continue; // Packet too short for Ethernet header
        }
        eth_hdr_t *eth = (eth_hdr_t *)packet;
        uint16_t ethertype = ntohs(eth->ethertype); // Convert ethertype to host byte order
        size_t offset = sizeof(eth_hdr_t); // Offset to next protocol header
        if (ethertype == 0x8100 && incl_len >= offset + 4) {
            // 802.1Q VLAN tag present: skip 4 bytes and read real ethertype
            offset += 4;
            ethertype = ntohs(*(uint16_t *)(packet + offset - 2));
        }
        if (ethertype != 0x0800) { // Only process IPv4 packets
            free(packet);
            continue;
        }

        // Parse IPv4 header
        if (incl_len < offset + sizeof(ipv4_hdr_t)) {
            free(packet);
            continue; // Packet too short for IPv4 header
        }
        ipv4_hdr_t *ip = (ipv4_hdr_t *)(packet + offset);
        uint8_t ihl = (ip->ver_ihl & 0x0F) * 4; // Calculate IP header length
        if (incl_len < offset + ihl) {
            free(packet);
            continue; // Packet too short for full IP header
        }
        if (ip->protocol != 17) { // Only process UDP packets (protocol number 17)
            free(packet);
            continue;
        }
        offset += ihl; // Move offset to UDP header

        // Parse UDP header
        if (incl_len < offset + sizeof(udp_hdr_t)) {
            free(packet);
            continue; // Packet too short for UDP header
        }
        udp_hdr_t *udp = (udp_hdr_t *)(packet + offset);
        uint16_t src_port = ntohs(udp->src_port);     // Source port
        uint16_t dst_port = ntohs(udp->dst_port);     // Destination port
        uint16_t udp_len = ntohs(udp->length);        // UDP length
        uint16_t checksum = ntohs(udp->checksum);     // UDP checksum

        // Print UDP header information
        printf("Src Port: %u\n", (unsigned)src_port);
        printf("Dst Port: %u\n", (unsigned)dst_port);
        printf("Length: %u\n", (unsigned)udp_len);
        printf("Checksum: 0x%04x\n", (unsigned)checksum);

        // Calculate UDP payload offset and length
        size_t udp_header_size = sizeof(udp_hdr_t);
        size_t payload_offset = offset + udp_header_size;
        size_t payload_file_len = (payload_offset <= incl_len) ? (incl_len - payload_offset) : 0;
        size_t payload_len = 0;
        if (udp_len >= udp_header_size) {
            payload_len = udp_len - udp_header_size;
        }
        // Limit payload length to what is present in the capture
        if (payload_len > payload_file_len) {
            payload_len = payload_file_len;
        }

        // Print UDP payload as ASCII, replacing non-printable characters with '.'
        for (size_t i = 0; i < payload_len; i++) {
            uint8_t c = packet[payload_offset + i];
            if (is_printable_ascii(c) && c != '\n' && c != '\r') {
                putchar((int)c);
            } else {
                putchar('.');
            }
        }
        putchar('\n');
        printf("==================================\n");

        free(packet); // Free memory for this packet
    }
    fclose(fp); // Close the PCAP file
    return 0;

}

