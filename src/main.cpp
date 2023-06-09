#include <iostream>
#include <stdexcept>

#include "rate_limiter.h"

int main() {
    RateLimiter rateLimiter;

    try {
        rateLimiter.processPcapFile(1, "../pcap_files/chargen-tcp.pcap", "output.pcap");
    } catch (const std::runtime_error& e) {
        std::cerr << e.what() << '\n';
    }
}
