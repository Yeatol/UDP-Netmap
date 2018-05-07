#include "udp_netmap.h"

#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <string>
#include <vector>
#include <mutex>
#include <thread>
#include <memory>
#include <atomic>
#include <algorithm>

#include <poll.h>
#include <unistd.h>
#include <ifaddrs.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define NETMAP_WITH_LIBS
#include <net/netmap_user.h>

#undef D
#define D(_fmt, ...)\
    do\
    {\
        struct timeval _t0;\
        gettimeofday(&_t0, NULL);\
        fprintf(stderr, "%03d.%06d " _fmt "\n", (int)(_t0.tv_sec % 1000), (int)_t0.tv_usec, ##__VA_ARGS__);\
    } while (0)

struct netmap_t
{
    nm_desc* d;
    mutex lock;
    netmap_t(nm_desc* v) { d = v; }
    ~netmap_t() { nm_close(d); }
};

static string ifname_;
static uint32_t if_ip_ = 0;
static uint64_t if_mac_ = 0;
static uint32_t if_netmask_ = 0;
static uint32_t gateway_ip_ = 0;
static uint64_t gateway_mac_ = 0xffffffffffff;
static vector<shared_ptr<netmap_t>> netmaps_;
static thread_local shared_ptr<netmap_t> netmap_;
static atomic_uint32_t ip_identification_ = 0;

static bool netmap_mode(const char* ifname)
{
    ifname_ = ifname;
    nm_desc* parent = nullptr;
    int if_queue_count = 1;
    char nm_name[1024] = {0};
    for (int i = 0; i < if_queue_count; ++i)
    {
        sprintf(nm_name, "netmap:%s-%d", ifname, i);
        nm_desc* d = nm_open(nm_name, 0, NETMAP_NO_TX_POLL | NETMAP_DO_RX_POLL, parent);
        if (i == 0)
        {
            parent = d;
            if_queue_count = parent->nifp->ni_rx_rings;
        }
        netmaps_.push_back(make_shared<netmap_t>(d));

        netmap_ring* rx = NETMAP_RXRING(d->nifp, i);
        netmap_ring* tx = NETMAP_TXRING(d->nifp, i);
        D("%s-%d: rx %d tx %d", ifname, i, rx->num_slots, tx->num_slots);
    }
    if (any_of(netmaps_.begin(), netmaps_.end(), [](auto i){ return i->d == nullptr; }))
    {
        netmaps_.clear();
    }
    return !netmaps_.empty();
}

static void frame_filter(u_char* arg, const nm_pkthdr* pkt, const u_char* buff);

static void netmap_thread(shared_ptr<netmap_t> netmap)
{
    netmap_ = netmap;
    pollfd rx_fd = { netmap_->d->fd, POLLIN , 0 };
    pollfd tx_fd = { netmap_->d->fd, POLLOUT, 0 };
    while(true)
    {
        while (poll(&rx_fd, 1, 5) < 0)
        {
            D("netmap poll rx falied! errno=%d", errno);
        }
        nm_dispatch(netmap_->d, -1, frame_filter, 0);
        while (poll(&tx_fd, 1, -1) < 0)
        {
            D("netmap poll tx falied! errno=%d", errno);
        }
    }
}

static void netmap_run()
{
    for(shared_ptr<netmap_t> netmap : netmaps_)
    {
        thread([=](){ netmap_thread(netmap); }).detach();
    }
}

static int nm_inject_ex(struct nm_desc *d, const void *buf1, size_t size1, const void *buf2, size_t size2)
{
    u_int c, n = d->last_tx_ring - d->first_tx_ring + 1, ri = d->cur_tx_ring;
    size_t size = size1 + size2;
    for (c = 0; c < n ; c++, ri++)
    {
        /* compute current ring to use */
        struct netmap_ring *ring;
        uint32_t i, idx;
        if (ri > d->last_tx_ring)
        {
            ri = d->first_tx_ring;
        }
        ring = NETMAP_TXRING(d->nifp, ri);
        if (nm_ring_empty(ring))
        {
            continue;
        }
        i = ring->cur;
        idx = ring->slot[i].buf_idx;
        ring->slot[i].len = size;
        char* nm_buf = NETMAP_BUF(ring, idx);
        nm_pkt_copy(buf1, nm_buf, size1);
        nm_pkt_copy(buf2, nm_buf + size1, size2);
        d->cur_tx_ring = ri;
        ring->head = ring->cur = nm_ring_next(ring, i);
        return size;
    }
    return 0; /* fail */
}

void netmap_output(char* head, uint32_t head_size, char* body, uint32_t body_size)
{
    shared_ptr<netmap_t> netmap = netmap_;
    if (netmap == nullptr)
    {
        static atomic_uint32_t i = 0;
        uint32_t index = i++ % netmaps_.size();
        netmap = netmaps_[index];
    }
    lock_guard<mutex> lock(netmap->lock);
    while(nm_inject_ex(netmap->d, head, head_size, body, body_size) == 0)
    {
        if (ioctl(netmap->d->fd, NIOCTXSYNC) == -1)
        {
            D("netmap ioctl NIOCTXSYNC falied! errno=%d", errno);
        }
    }
}

#pragma pack(push,1)
// +----------------------------------------------------------------+
// | EthernetII| 0800-IPv4 0806-ARP 0835-RARP                       |
// +-----------+------+----------+--------+------+------------+-----+
// |  Preamble | SFD  | 目标地址 | 源地址 | 类型 |    数据    | FCS |
// +-----------+------+----------+--------+------+------------+-----+
// |     7     |  1   |    6     |   6    |  2   |   46-1500  |  4  |
// +-----------+------+----------+--------+------+------------+-----+

struct ether_t
{
    uint64_t  dst_mac:48;
    uint64_t  src_mac:48;
    uint16_t  protocol;

    static const uint16_t ip   = 0x0008; // 0x08 0x00
    static const uint16_t arp  = 0x0608; // 0x08 0x06
    static const uint16_t rarp = 0x3508; // 0x08 0x35
};

// +--------------------------------------------------------------------------------------------------------------------+
// | ARP/RARP |                                                                                                         |
// +----------+----------+--------------+--------------+--------+------------+------------+--------------+--------------+
// | 硬件类型 | 协议类型 | 物理地址长度 | 协议地址长度 | 操作码 | 源物理地址 | 源协议地址 | 目标物理地址 | 目标协议地址 |
// +----------+----------+--------------+--------------+--------+------------+------------+--------------+--------------+
// |     2    |    2     |      1       |      1       |   2    |     6      |     6      |      4       |      4       |
// +----------+----------+--------------+--------------+--------+------------+------------+--------------+--------------+
// 操作码
// 1 ARP请求
// 2 ARP响应
// 3 RARP请求
// 4 RARP响应
struct arp_t
{
    uint16_t hardware_type;
    uint16_t protocol_type;
    uint8_t  hardware_size;
    uint8_t  protocol_size;
    uint16_t opcode;
    uint64_t src_mac:48;
    uint32_t src_ip;
    uint64_t dst_mac:48;
    uint32_t dst_ip;
};

// +-----------------------------------------------------+
// |      ICMP       |                                   |
// +-----------------+-------------+--------+------------+
// |       类型      |     代码    | 校验和 |    数据    |
// +-----------------+-------------+--------+------------+
// |        1        |      1      |   2    |            |
// +-----------------+-------------+--------+------------+
// 查询                 差错
// 8  回显请求          3  目标不可达
// 0  回显应答          4  源抑制
// 9  路由器公告        5  重定向
// 10 路由器请求        11 超时
// 17 地址掩码请求
// 18 地址掩码应答
struct icmp_t
{
    uint8_t  type;
    uint8_t  code;
    uint16_t checksum;
};

// +------------------------------------------------------------+
// |       IP        |                                          |
// +-----------------+-------------+------+--------+------------+
// |   版本/首部长度 |   首部长度  | 长度 | 校验和 |    数据    |
// +-----------------+-------------+------+--------+------------+
// |        1        |      4      |  2   |   2    |            |
// +-----------------+-------------+------+--------+------------+


struct ip_t
{
    uint8_t  hlength:4;
    uint8_t  version:4;
    uint8_t  tos;
    uint16_t total_length;
    uint16_t identification;
    uint8_t  flags:3;
    uint16_t fragment_offset:13;
    uint8_t  ttl;
    uint8_t  protocol;
    uint16_t hchecksum;
    uint32_t src_ip;
    uint32_t dst_ip;

    static const uint8_t  icmp = 1;
    static const uint8_t  tcp  = 6;
    static const uint8_t  udp  = 17;
};

// +------------------------------------------------------+
// |    UDP    |                                          |
// +-----------+-------------+------+--------+------------+
// |   源端口  |   目标端口  | 长度 | 校验和 |    数据    |
// +-----------+-------------+------+--------+------------+
// |     2     |      2      |  2   |   2    |            |
// +-----------+-------------+------+--------+------------+
struct udpcsum_t
{
    uint32_t src_ip;
    uint32_t dst_ip;
    uint8_t  padding;
    uint8_t  protocol;
    uint16_t length;
};

struct udp_t
{
    uint16_t src_port;
    uint16_t dst_port;
    uint16_t length;
    uint16_t checksum;
};

struct frame_t
{
    ether_t* ether;
    ip_t*    ip;
    arp_t*   arp;
    icmp_t*  icmp;
    udp_t*   udp;
    char*    udp_data;
    uint32_t udp_size;
};

struct arp_head
{
    ether_t  ether;
    arp_t    arp;
};

struct udp_head
{
    ether_t  ether;
    ip_t     ip;
    udp_t    udp;
};

#pragma pack(pop)

static string mac_to_string(uint64_t mac)
{
    uint8_t* x = (uint8_t*)&mac;
    char mac_string[18];
    for (int i = 0; i < 6; ++i)
    {
        sprintf(mac_string + i * 3, "%02x", *(x + i));
        mac_string[i*3+2] = ':';
    }
    mac_string[17] = 0;
    return mac_string;
}

static string ip_to_string(uint32_t ip)
{
    return inet_ntoa(in_addr{ip});
}

static uint32_t string_to_ip(const char* ip)
{
    in_addr_t addr = inet_addr(ip);
    return (uint32_t)addr;
}

static frame_t frame_map(char* data, uint32_t size)
{
    frame_t frame = {0};
    uint32_t offset   = 0;
    frame.ether = (ether_t*)(data + offset);
    offset += sizeof(ether_t);
    if (frame.ether->protocol == ether_t::ip)
    {
        frame.ip = (ip_t*)(data + offset);
        offset += frame.ip->hlength * 4;
        if (frame.ip->protocol == ip_t::udp)
        {
            frame.udp = (udp_t*)(data + offset);
            offset += sizeof(udp_t);
            frame.udp_data = (data + offset);
            frame.udp_size = ntohs(frame.udp->length) - sizeof(udp_t);
        }
        else if (frame.ip->protocol == ip_t::icmp)
        {
            frame.icmp = (icmp_t*)(data + offset);
        }
    }
    else if (frame.ether->protocol == ether_t::arp || frame.ether->protocol == ether_t::rarp)
    {
        frame.arp = (arp_t*)(data + sizeof(ether_t));
    }

    if (frame.ether)
    {
        D("");
        D("EtherneII");
        D("    dst_mac         : %s",     mac_to_string(frame.ether->dst_mac).c_str());
        D("    src_mac         : %s",     mac_to_string(frame.ether->src_mac).c_str());
        D("    protocol        : 0x%04x", ntohs(frame.ether->protocol));
    }
    if (frame.arp)
    {
        D("ARP");
        D("    hardware_type   : 0x%04x", ntohs(frame.arp->hardware_type));
        D("    protocol_type   : 0x%04x", ntohs(frame.arp->protocol_type));
        D("    hardware_size   : %d",     frame.arp->hardware_size);
        D("    protocol_size   : %d",     frame.arp->protocol_size);
        D("    opcode          : 0x%04x", frame.arp->opcode);
        D("    src_mac         : %s",     mac_to_string(frame.arp->src_mac).c_str());
        D("    src_ip          : %s",     ip_to_string(frame.arp->src_ip).c_str());
        D("    dst_mac         : %s",     mac_to_string(frame.arp->dst_mac).c_str());
        D("    dst_ip          : %s",     ip_to_string(frame.arp->dst_ip).c_str());
    }
    if (frame.ip)
    {
        D("IP");
        D("    hlength         : %d",     frame.ip->hlength);
        D("    version         : 0x%02x", frame.ip->version);
        D("    tos             : 0x%02x", frame.ip->tos);
        D("    total_length    : %d",     ntohs(frame.ip->total_length));
        D("    identification  : 0x%04x", ntohs(frame.ip->identification));
        D("    flags           : 0x%02x", frame.ip->flags);
        D("    fragment_offset : 0x%04x", ntohs(frame.ip->fragment_offset));
        D("    ttl             : %d",     frame.ip->ttl);
        D("    protocol        : %d",     frame.ip->protocol);
        D("    checksum        : 0x%04x", ntohs(frame.ip->hchecksum));
        D("    src_ip          : %s",     ip_to_string(frame.ip->src_ip).c_str());
        D("    dst_ip          : %s",     ip_to_string(frame.ip->dst_ip).c_str());
    }
    if (frame.icmp)
    {
        D("ICMP");
        D("    type            : 0x%02x", frame.icmp->type);
        D("    code            : 0x%02x", frame.icmp->code);
        D("    checksum        : 0x%04x", ntohs(frame.icmp->checksum));
    }
    if (frame.udp)
    {
        D("UDP");
        D("    src_port        : %d",     ntohs(frame.udp->src_port));
        D("    dst_port        : %d",     ntohs(frame.udp->dst_port));
        D("    length          : %d",     ntohs(frame.udp->length));
        D("    checksum        : 0x%04x", ntohs(frame.udp->checksum));
    }

    return frame;
}

static uint16_t checksum(uint16_t* data, int size)
{
    uint32_t checksum = 0;
    while (size > 1)
    {
        checksum += *data++;
        size -= sizeof(uint16_t);
    }
    if (size)
    {
        checksum += *(uint8_t*)data;
    }
    checksum = (checksum >> 16) + (checksum & 0xffff);
    checksum += (checksum >> 16);
    return (uint16_t)(~checksum);
}

static void ip_checksum(ip_t* ip)
{
    ip->hchecksum = 0;
    ip->ttl = 64;
    int size = ip->hlength * 4;
    ip->hchecksum = checksum((uint16_t*)ip, size);
}

static void icmp_checksum(icmp_t* icmp, int size)
{
    icmp->checksum = 0;
    icmp->checksum = checksum((uint16_t*)icmp, size);
}

static void udp_checksum(ip_t* ip, udp_t* udp, char* data, int size)
{
    udp->checksum = 0;
    udpcsum_t udpcsum = { ip->src_ip, ip->dst_ip, 0x00, 17, udp->length};
    uint16_t* pudpcsum = (uint16_t*)&udpcsum;
    uint16_t* pudp = (uint16_t*)udp;
    uint16_t* pdata = (uint16_t*)data;
    uint32_t checksum = 0;
    for (int i = 0; i < 6; ++i)
    {
        checksum += *pudpcsum++;
    }
    for (int i = 0; i < 4; ++i)
    {
        checksum += *pudp++;
    }
    while (size > 1)
    {
        checksum += *pdata++;
        size -= sizeof(uint16_t);
    }
    if (size)
    {
        checksum += *(uint8_t*)pdata;
    }
    checksum = (checksum >> 16) + (checksum & 0xffff);
    checksum += (checksum >> 16);
    checksum = (uint16_t)(~checksum);
    udp->checksum = checksum;
}

static bool if_address(string ifname, uint64_t& if_mac, uint32_t& if_ip, uint32_t& if_netmask)
{
    ifaddrs* ifalist = 0;
    if (getifaddrs(&ifalist) < 0) return false;
    for(ifaddrs* ifa = ifalist; ifa != 0; ifa = ifa->ifa_next)
    {
        if (ifa->ifa_name == ifname)
        {
            if (ifa->ifa_addr->sa_family == AF_LINK)
            {
                sockaddr_dl* addr = (sockaddr_dl*)ifa->ifa_addr;
                memcpy(&if_mac, addr->sdl_data + addr->sdl_nlen, 6);
            }
            if (ifa->ifa_addr->sa_family == AF_INET)
            {
                sockaddr_in* addr = (sockaddr_in*)ifa->ifa_addr;
                if_ip = addr->sin_addr.s_addr;
                sockaddr_in* netmask = (sockaddr_in*)ifa->ifa_netmask;
                if_netmask = netmask->sin_addr.s_addr;
            }
        }
    }
    freeifaddrs(ifalist);
    return true;
}

static void network_output(char* head, uint32_t head_size, char* data = 0, uint32_t data_size = 0)
{
    frame_t frame = frame_map((char*)head, head_size);
    netmap_output(head, head_size, data, data_size);
}

static void frame_filter(u_char* arg, const nm_pkthdr* pkt, const u_char* buff)
{
    char* data = (char*)buff;
    uint32_t size = pkt->len;
    frame_t frame = frame_map(data, size);
    // ARP
    if (frame.arp && frame.arp->hardware_type == 0x0100 && frame.arp->protocol_type == 0x0008 && frame.arp->hardware_size == 6 && frame.arp->protocol_size == 4)
    {
        // 回应本机MAC
        if (frame.arp->dst_ip == if_ip_ && frame.arp->opcode == 0x0100)
        {
            gateway_mac_ = frame.arp->src_mac;
            frame.ether->dst_mac = frame.ether->src_mac;
            frame.ether->src_mac = if_mac_;
            frame.arp->dst_mac = frame.ether->dst_mac;
            frame.arp->src_mac = frame.ether->src_mac;
            frame.arp->dst_ip = frame.arp->src_ip;
            frame.arp->src_ip = if_ip_;
            frame.arp->opcode = 0x0200;
            network_output(data, size);
        }
        // 记录网关MAC
        if (frame.arp->src_ip == gateway_ip_ && frame.arp->opcode == 0x0200)
        {
            gateway_mac_ = frame.arp->src_mac;
        }
    }
    // ICMP
    if (frame.icmp && frame.icmp->type == 0x08)
    {
        frame.ether->dst_mac = frame.ether->src_mac;
        frame.ether->src_mac = if_mac_;
        frame.ip->dst_ip = frame.ip->src_ip;
        frame.ip->src_ip = if_ip_;
        frame.ip->identification = htons(ip_identification_++);
        frame.icmp->type = 0x00;
        ip_checksum(frame.ip);
        icmp_checksum(frame.icmp, ntohs(frame.ip->total_length) - frame.ip->hlength * 4);
        network_output(data, size);
    }
    // UDP
    if (frame.ether && frame.ip && frame.udp && frame.udp->dst_port > 1024)
    {
        udp_input(frame.ip->src_ip, ntohs(frame.udp->src_port), ntohs(frame.udp->dst_port), frame.udp_data, frame.udp_size);
    }
}

static void arp_update_gateway()
{
    arp_head head;
    head.ether.dst_mac = gateway_mac_;
    head.ether.src_mac = if_mac_;
    head.ether.protocol = 0x0608;
    head.arp.hardware_type = 0x0100;
    head.arp.protocol_type = 0x0008;
    head.arp.hardware_size = 0x06;
    head.arp.protocol_size = 0x04;
    head.arp.opcode = 0x0100;
    head.arp.src_mac = if_mac_;
    head.arp.src_ip = if_ip_;
    head.arp.dst_mac = gateway_mac_ == 0xffffffffffff ? 0 : gateway_mac_;
    head.arp.dst_ip = gateway_ip_;
    network_output((char*)&head, sizeof(arp_head));
}

void udp_update(uint32_t current)
{
    arp_update_gateway();
}

void udp_config(const char* ifname, const char* gateway_ip)
{
    ifname_ = ifname;
    gateway_ip_ = string_to_ip(gateway_ip);
    if_address(ifname_, if_mac_, if_ip_, if_netmask_);
    D("%s: ip:%s netmask:%s mac:%s gateway:%s", ifname_.c_str(), ip_to_string(if_ip_).c_str(), ip_to_string(if_netmask_).c_str(), mac_to_string(if_mac_).c_str(), ip_to_string(gateway_ip_).c_str());
    netmap_mode(ifname);
    netmap_run();
}

void udp_output(uint32_t dst_ip, uint16_t dst_port, uint16_t src_port, void* data, uint32_t size)
{
    udp_head head;
    head.ether.dst_mac = gateway_mac_;
    head.ether.src_mac = if_mac_;
    head.ether.protocol = 0x0008;
    head.ip.hlength = 5;
    head.ip.version = 0x04;
    head.ip.tos = 0x00;
    head.ip.total_length = htons(head.ip.hlength * 4 + sizeof(udp_t) + size);
    head.ip.identification = htons(ip_identification_++);
    head.ip.flags = 0x00;
    head.ip.fragment_offset = 0x0000;
    head.ip.ttl = 64;
    head.ip.protocol = 17;
    head.ip.hchecksum = 0;
    head.ip.src_ip = if_ip_;
    head.ip.dst_ip = dst_ip;
    head.udp.src_port = htons(src_port);
    head.udp.dst_port = htons(dst_port);
    head.udp.length = htons(sizeof(udp_t) + size);
    head.udp.checksum = 0;
    ip_checksum(&head.ip);
    udp_checksum(&head.ip, &head.udp, (char*)data, size);
    network_output((char*)&head, sizeof(udp_head), (char*)data, size);
}
