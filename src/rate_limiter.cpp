#include "rate_limiter.h"

#include <chrono>
#include <fstream>
#include <stdexcept>
#include <string>
#include <vector>

#include "pcap_packet.h"

RateLimiter::RateLimiter():
    tokens_(0)
{}

void RateLimiter::processPcapFile(double limitMbps, const std::string& inputFileName, const std::string& outputFileName) {
    if (limitMbps <= 0.0) {
        throw std::runtime_error("Limit Mbps must be greater than 0");
    }

    std::ifstream inputFile(inputFileName, std::ios::binary);
    if (!inputFile.is_open()) {
        throw std::runtime_error("Failed to open input pcap file: " + inputFileName);
    }

    std::ofstream outputFile(outputFileName, std::ios::binary);
    if (!outputFile.is_open()) {
        throw std::runtime_error("Failed to open output pcap file: " + outputFileName);
    }

    PcapFileHeader fileHeader;
    if (!inputFile.read(reinterpret_cast<char*>(&fileHeader), sizeof(fileHeader))) {
        throw std::runtime_error("Failed to read input pcap file header");
    }
    outputFile.write(reinterpret_cast<char*>(&fileHeader), sizeof(fileHeader));

    PcapPacketHeader packetHeader;
    lastRefillTime_ = std::chrono::high_resolution_clock::now();
    while (inputFile.read(reinterpret_cast<char*>(&packetHeader), sizeof(packetHeader))) {
        const double packetSizeMbps = calculatePacketSizeMbps(packetHeader);
        refillTokens(limitMbps);

        const double requiredTokens = packetSizeMbps;
        while (tokens_ < requiredTokens) {
            refillTokens(limitMbps);
        }
        tokens_ -= requiredTokens;

        std::vector<char> buffer;
        buffer.reserve(packetHeader.incl_len);
        if (!inputFile.read(buffer.data(), packetHeader.incl_len)) {
            throw std::runtime_error("Failed to read packet data");
        }

        outputFile.write(reinterpret_cast<char*>(&packetHeader), sizeof(packetHeader));
        outputFile.write(buffer.data(), packetHeader.incl_len);
    }
}

constexpr auto BYTES_TO_MBITPS = 8.0 / 1048576.0;

constexpr double RateLimiter::calculatePacketSizeMbps(const PcapPacketHeader& packetHeader) {
    const auto packetSizeBytes = static_cast<double>(packetHeader.orig_len);
    const double packetSizeMbps = packetSizeBytes * BYTES_TO_MBITPS;
    return packetSizeMbps;
}

void RateLimiter::refillTokens(double limitMbps) {
    const auto now = std::chrono::high_resolution_clock::now();
    const std::chrono::duration<double> timePassed = now - lastRefillTime_;
    const double tokensToAdd = timePassed.count() * limitMbps;

    tokens_ = std::min(tokens_ + tokensToAdd, limitMbps);
    lastRefillTime_ = now;
}
