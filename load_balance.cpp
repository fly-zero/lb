#include <arpa/inet.h>
#include <netinet/ether.h>
#include <netinet/ip.h>

#include <iostream>
#include <iomanip>

#include <pcap.h>

/**
 * @brief 转换参数n的字节序
 * @note 使用consexper声明来支持编译时完成转换
 */
constexpr uint16_t swap_bytes(uint16_t n) { return (n << 8 | n >> 8); }

inline std::tuple<const char *, bool> ether_type_to_str(uint16_t type)
{
    switch (type)
    {
    case swap_bytes(ETHERTYPE_IP):
        return { "ip", true };

    case swap_bytes(ETHERTYPE_ARP):
        return { "arp", true };

    case swap_bytes(ETHERTYPE_IPV6):
        return { "ipv6", true };

    default:
        return { "nil", false };
    }
}

inline std::ostream & operator<<(std::ostream & os, const ether_header & ether_hdr)
{
    auto const flags = os.flags();

    const char * ether_type;
    std::tie(ether_type, std::ignore) = ether_type_to_str(ether_hdr.ether_type);

    os << "ether [" << std::hex << std::setw(2) << std::setfill('0')
       << static_cast<int>(ether_hdr.ether_shost[0]) << ':' << std::setw(2)
       << std::setfill('0') << static_cast<int>(ether_hdr.ether_shost[1]) << ':'
       << std::setw(2) << std::setfill('0')
       << static_cast<int>(ether_hdr.ether_shost[2]) << ':' << std::setw(2)
       << std::setfill('0') << static_cast<int>(ether_hdr.ether_shost[3]) << ':'
       << std::setw(2) << std::setfill('0')
       << static_cast<int>(ether_hdr.ether_shost[4]) << ':' << std::setw(2)
       << std::setfill('0') << static_cast<int>(ether_hdr.ether_shost[5])
       << " => " << std::setw(2) << std::setfill('0')
       << static_cast<int>(ether_hdr.ether_dhost[0]) << ':' << std::setw(2)
       << std::setfill('0') << static_cast<int>(ether_hdr.ether_dhost[1]) << ':'
       << std::setw(2) << std::setfill('0')
       << static_cast<int>(ether_hdr.ether_dhost[2]) << ':' << std::setw(2)
       << std::setfill('0') << static_cast<int>(ether_hdr.ether_dhost[3]) << ':'
       << std::setw(2) << std::setfill('0')
       << static_cast<int>(ether_hdr.ether_dhost[4]) << ':' << std::setw(2)
       << std::setfill('0') << static_cast<int>(ether_hdr.ether_dhost[5]) << ']'
       << std::setfill(' ') << std::setw(5) << ether_type << "(0x"
       << std::setw(4) << std::setfill('0') << ntohs(ether_hdr.ether_type)
       << ')';

    os.flags(flags);
    return os;
}

inline std::ostream & operator<<(std::ostream & os, const iphdr & ip_hdr)
{
    char saddr_buf[16], daddr_buf[16];
    inet_ntop(AF_INET, &ip_hdr.saddr, saddr_buf, sizeof saddr_buf);
    inet_ntop(AF_INET, &ip_hdr.daddr, daddr_buf, sizeof daddr_buf);
    auto const flags = os.flags();
    os << std::setw(15) << std::setfill(' ') << saddr_buf << " => " << daddr_buf;
    os.flags(flags);
    return os;
}

static void my_pcap_handler(u_char * user, const pcap_pkthdr * h, const u_char * bytes)
{
    auto const bgn = bytes;
    auto const end = bytes + h->caplen;

    auto p    = bgn;
    auto next = p + sizeof(ether_header);
    if (next > end)
    {
        std::cerr << "bad ether packet, caplen=" << h->caplen << std::endl;
        return;
    }

    bool       ok;
    auto const ether_hdr      = reinterpret_cast<const ether_header *>(p);
    std::tie(std::ignore, ok) = ether_type_to_str(ether_hdr->ether_type);
    if (!ok)
    {
        std::cerr << "unknown ether type, " << *ether_hdr << std::endl;
        return;
    }

    // 仅处理IPv4
    if (ether_hdr->ether_type != swap_bytes(ETHERTYPE_IP))
    {
        std::cout << *ether_hdr << std::endl;
        return;
    }

    p    = next;
    next = p + sizeof (iphdr);
    if (next > end)
    {
        std::cerr << "bad ip packet" << std::endl;
        return;
    }

    auto const ip_hdr = reinterpret_cast<const iphdr *>(p);
    std::cout << *ether_hdr << ' ' << *ip_hdr << std::endl;
}

int main(int argc, char **argv)
{
    auto const device = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    auto const pcap = pcap_open_live(device, 65535, 0, 500, errbuf);
    if (!pcap)
    {
        std::cerr << "pcap_open_live failed, " << errbuf << std::endl;
        return -1;
    }

    while (true)
    {
        auto const err = pcap_dispatch(pcap, -1, my_pcap_handler, nullptr);
        if (err < 0)
        {
            std::cerr << "pcap_dispatch failed, err=" << err << ", " << pcap_geterr(pcap) << std::endl;
            break;
        }
    }

    pcap_close(pcap);

    return 0;
}