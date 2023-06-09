#ifndef PCAP_PACKET_H
#define PCAP_PACKET_H

#include <cstdint>

#pragma pack(push, 1)
struct PcapFileHeader {
    uint32_t magic_number;
    uint16_t version_major;
    uint16_t version_minor;
    int32_t thiszone;
    uint32_t sigfigs;
    uint32_t snaplen;
    uint32_t network;
};
#pragma pack(pop)

#pragma pack(push, 1)
struct PcapPacketHeader {
    uint32_t ts_sec;
    uint32_t ts_usec;
    uint32_t incl_len;
    uint32_t orig_len;
};
#pragma pack(pop)

#endif //PCAP_PACKET_H
