#include "gtest/gtest.h"

#include <fstream>
#include <stdexcept>
#include <string>

#include "rate_limiter.h"
#include "pcap_packet.h"

TEST(RateLimiter, BadLimit) {
    RateLimiter rateLimiter;
    EXPECT_THROW(rateLimiter.processPcapFile(-1.0, "../pcap_files/bfd-raw-auth-simple.pcap", "out.pcap"), std::runtime_error);
}

TEST(RateLimiter, BadInputFile) {
    RateLimiter rateLimiter;
    EXPECT_THROW(rateLimiter.processPcapFile(10.0, "../pcap_files/15564645616.pcap", "out.pcap"), std::runtime_error);
}

TEST(SizeMbpsCalculator, ZeroIsZero) {
    PcapPacketHeader packetHeader{};
    EXPECT_EQ(0, RateLimiter::calculatePacketSizeMbps(packetHeader));
}

TEST(SizeMbpsCalculator, CorrectSize) {
    PcapPacketHeader packetHeader{};
    packetHeader.orig_len = 10 * 1024 * 1024;
    EXPECT_EQ(10 * 8, RateLimiter::calculatePacketSizeMbps(packetHeader));
}

TEST(RateLimiter, AllGood) {
    RateLimiter rateLimiter;
    const std::string inputFileName = "../pcap_files/bfd-raw-auth-simple.pcap";
    const std::string outputFileName = "out.pcap";

    EXPECT_NO_THROW(rateLimiter.processPcapFile(10.0, "../pcap_files/bfd-raw-auth-simple.pcap", "out.pcap"));

    std::ifstream inputFile(inputFileName);
    std::ifstream outputFile(outputFileName);

    EXPECT_TRUE(inputFile && outputFile && (inputFile.peek() == outputFile.peek()));

    while (inputFile && outputFile) {
        EXPECT_EQ(inputFile.get(), outputFile.get());
    }

    EXPECT_TRUE(inputFile.eof() && outputFile.eof());
}
