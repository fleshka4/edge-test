#ifndef RATE_LIMITER_H
#define RATE_LIMITER_H

#include <chrono>
#include <string>

struct PcapPacketHeader;

class RateLimiter {
public:
    RateLimiter();

    void processPcapFile(double limitMbps, const std::string& inputFileName, const std::string& outputFileName);

    [[nodiscard]] constexpr static double calculatePacketSizeMbps(const PcapPacketHeader& packetHeader);
private:
    void refillTokens(double limitMbps);

private:
    double tokens_;
    std::chrono::high_resolution_clock::time_point lastRefillTime_;
};

#endif //RATE_LIMITER_H
