#include "gtest/gtest.h"

#include <fstream>
#include <stdexcept>
#include <string>

#include "rate_limiter.h"
#include "pcap_packet.h"

TEST(SizeMbpsCalculator, ZeroIsZero) {
    PcapPacketHeader packetHeader{};
    EXPECT_EQ(0, RateLimiter::calculatePacketSizeMbps(packetHeader));
}

TEST(SizeMbpsCalculator, CorrectSize) {
    PcapPacketHeader packetHeader{};
    packetHeader.orig_len = 10 * 1024 * 1024;
    EXPECT_EQ(10 * 8, RateLimiter::calculatePacketSizeMbps(packetHeader));
}

class RateLimiterTestFixture : public testing::Test {
protected:
    RateLimiter rateLimiter;

    const std::string inputFileName = "../pcap_files/bfd-raw-auth-simple.pcap";
    const std::string outputFileName = "out.pcap";
};

TEST_F(RateLimiterTestFixture, BadLimit) {
    EXPECT_THROW(rateLimiter.processPcapFile(-1.0, inputFileName, outputFileName), std::runtime_error);
}

TEST_F(RateLimiterTestFixture, BadInputFile) {
    EXPECT_THROW(rateLimiter.processPcapFile(10.0, "../pcap_files/15564645616.pcap", outputFileName), std::runtime_error);
}

TEST_F(RateLimiterTestFixture, AllGood) {
    EXPECT_NO_THROW(rateLimiter.processPcapFile(10.0, inputFileName, outputFileName));

    std::ifstream inputFile(inputFileName);
    std::ifstream outputFile(outputFileName);

    EXPECT_TRUE(inputFile && outputFile && (inputFile.peek() == outputFile.peek()));

    while (inputFile && outputFile) {
        EXPECT_EQ(inputFile.get(), outputFile.get());
    }

    EXPECT_TRUE(inputFile.eof() && outputFile.eof());
}
