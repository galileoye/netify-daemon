// Netify Agent
// Copyright (C) 2015-2018 eGloo Incorporated <http://www.egloo.ca>
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <http://www.gnu.org/licenses/>.

#ifdef HAVE_CONFIG_H
#include "config.h"
#endif

#include <vector>
#include <map>
#include <unordered_map>
#include <stdexcept>

#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <signal.h>
#include <errno.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netdb.h>
#include <pthread.h>

#if defined(HAVE_LINUX_NETLINK_H)
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#endif
#if defined (_ND_USE_NETLINK_BSD)
#include <sys/sysctl.h>
#include <net/if_dl.h>
#include <net/route.h>

#define _ND_NETLINK_ALIGN(a) \
    ((a) > 0 ? (1 + (((a) - 1) | (sizeof(unsigned long) - 1))) : sizeof(unsigned long))
#define _ND_NETLINK_NEXTSA(s) \
    ((struct sockaddr *)((uint8_t *)(s) + _ND_NETLINK_ALIGN((s)->sa_len)))
#endif

using namespace std;

#include "ndpi_main.h"

#include "netifyd.h"
#include "nd-util.h"
#include "nd-netlink.h"

extern nd_global_config nd_config;

inline bool ndNetlinkNetworkAddr::operator==(const ndNetlinkNetworkAddr &n) const
{
    int rc = -1;
    const struct sockaddr_in *ipv4_addr1, *ipv4_addr2;
    const struct sockaddr_in6 *ipv6_addr1, *ipv6_addr2;

    if (this->length != n.length)
        return false;

    if (this->network.ss_family != n.network.ss_family)
        return false;

    switch (this->network.ss_family) {
    case AF_INET:
        ipv4_addr1 = reinterpret_cast<const struct sockaddr_in *>(&this->network);
        ipv4_addr2 = reinterpret_cast<const struct sockaddr_in *>(&n.network);
        rc = memcmp(
            &ipv4_addr1->sin_addr, &ipv4_addr2->sin_addr, sizeof(struct in_addr));
        break;
    case AF_INET6:
        ipv6_addr1 = reinterpret_cast<const struct sockaddr_in6 *>(&this->network);
        ipv6_addr2 = reinterpret_cast<const struct sockaddr_in6 *>(&n.network);
        rc = memcmp(
            &ipv6_addr1->sin6_addr, &ipv6_addr2->sin6_addr, sizeof(struct in6_addr));
        break;
    default:
        return false;
    }

    return (rc == 0);
}

inline bool ndNetlinkNetworkAddr::operator!=(const ndNetlinkNetworkAddr &n) const
{
    int rc = -1;
    const struct sockaddr_in *ipv4_addr1, *ipv4_addr2;
    const struct sockaddr_in6 *ipv6_addr1, *ipv6_addr2;

    if (this->length != n.length)
        return true;

    if (this->network.ss_family != n.network.ss_family)
        return true;

    switch (this->network.ss_family) {
    case AF_INET:
        ipv4_addr1 = reinterpret_cast<const struct sockaddr_in *>(&this->network);
        ipv4_addr2 = reinterpret_cast<const struct sockaddr_in *>(&n.network);
        rc = memcmp(
            &ipv4_addr1->sin_addr, &ipv4_addr2->sin_addr, sizeof(struct in_addr));
        break;
    case AF_INET6:
        ipv6_addr1 = reinterpret_cast<const struct sockaddr_in6 *>(&this->network);
        ipv6_addr2 = reinterpret_cast<const struct sockaddr_in6 *>(&n.network);
        rc = memcmp(
            &ipv6_addr1->sin6_addr, &ipv6_addr2->sin6_addr, sizeof(struct in6_addr));
        break;
    default:
        return true;
    }

    return (rc != 0);
}

ndNetlink::ndNetlink(const nd_ifaces &ifaces)
    : nd(-1), seq(0), buffer(NULL), buffer_length(_ND_NETLINK_BUFSIZ)
{
    int rc;

    buffer = (uint8_t *)realloc(NULL, buffer_length);
    if (buffer == NULL) throw ndNetlinkException(strerror(ENOMEM));
    memset(buffer, 0, buffer_length);

#ifndef _ND_USE_NETLINK_BSD
    memset(&sa, 0, sizeof(struct sockaddr_nl));
    sa.nl_family = AF_NETLINK;
    sa.nl_pid = getpid();
    sa.nl_groups =
        RTMGRP_IPV4_ROUTE | RTMGRP_IPV6_ROUTE |
        RTMGRP_IPV4_IFADDR | RTMGRP_IPV6_IFADDR;

    nd = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (nd < 0) {
        rc = errno;
        nd_printf("Error creating netlink socket: %s\n", strerror(rc));
        throw ndNetlinkException(strerror(rc));
    }

    if (bind(nd,
        (struct sockaddr *)&sa, sizeof(struct sockaddr_nl)) < 0) {
        rc = errno;
        nd_printf("Error binding netlink socket: %s\n", strerror(rc));
        throw ndNetlinkException(strerror(rc));
    }
#else
    memset(&sa, 0, sizeof(struct sockaddr_dl));

    nd = socket(AF_ROUTE, SOCK_RAW, AF_UNSPEC);
    if (nd < 0) {
        rc = errno;
        nd_printf("Error creating netlink socket: %s\n", strerror(rc));
        throw ndNetlinkException(strerror(rc));
    }
#endif
    if (fcntl(nd, F_SETOWN, getpid()) < 0) {
        rc = errno;
        nd_printf("Error setting netlink socket owner: %s\n", strerror(rc));
        throw ndNetlinkException(strerror(errno));
    }
#ifdef F_SETSIG
    if (fcntl(nd, F_SETSIG, SIGIO) < 0) {
        rc = errno;
        nd_printf("Error setting netlink I/O signal: %s\n", strerror(rc));
        throw ndNetlinkException(strerror(errno));
    }
#endif
    int flags = fcntl(nd, F_GETFL);
    if (fcntl(nd, F_SETFL, flags | O_ASYNC | O_NONBLOCK) < 0) {
        rc = errno;
        nd_printf("Error setting netlink socket flags: %s\n", strerror(rc));
        throw ndNetlinkException(strerror(rc));
    }

    for (nd_ifaces::const_iterator i = ifaces.begin(); i != ifaces.end(); i++)
        AddInterface((*i).second);

    // Add private networks for when all else fails...
    AddNetwork(AF_INET, _ND_NETLINK_PRIVATE, "10.0.0.0", 8);
    AddNetwork(AF_INET, _ND_NETLINK_PRIVATE, "172.16.0.0", 12);
    AddNetwork(AF_INET, _ND_NETLINK_PRIVATE, "192.168.0.0", 16);
    AddNetwork(AF_INET6, _ND_NETLINK_PRIVATE, "fc00::", 7);

    // Add multicast networks
    AddNetwork(AF_INET, _ND_NETLINK_MULTICAST, "224.0.0.0", 4);
    AddNetwork(AF_INET6, _ND_NETLINK_MULTICAST, "ff00::", 8);

    // Add broadcast addresses
    AddInterface(_ND_NETLINK_BROADCAST);
    AddAddress(AF_INET, _ND_NETLINK_BROADCAST, "169.254.255.255");
    AddAddress(AF_INET, _ND_NETLINK_BROADCAST, "255.255.255.255");
}

ndNetlink::~ndNetlink()
{
    if (nd >= 0) close(nd);
    for (ndNetlinkInterfaces::const_iterator i = ifaces.begin();
        i != ifaces.end(); i++) {
        if (i->second != NULL) {
            pthread_mutex_destroy(i->second);
            delete i->second;
        }
    }

    free(buffer);
}

void ndNetlink::PrintType(const string &prefix, const ndNetlinkAddressType &type)
{
    switch (type) {
    case ndNETLINK_ATYPE_UNKNOWN:
        nd_printf("%s: address is: UNKNOWN\n", prefix.c_str());
        break;
    case ndNETLINK_ATYPE_LOCALIP:
        nd_printf("%s: address is: LOCALIP\n", prefix.c_str());
        break;
    case ndNETLINK_ATYPE_LOCALNET:
        nd_printf("%s: address is: LOCALNET\n", prefix.c_str());
        break;
    case ndNETLINK_ATYPE_PRIVATE:
        nd_printf("%s: address is: PRIVATE\n", prefix.c_str());
        break;
    case ndNETLINK_ATYPE_MULTICAST:
        nd_printf("%s: address is: MULTICAST\n", prefix.c_str());
        break;
    case ndNETLINK_ATYPE_BROADCAST:
        nd_printf("%s: address is: BROADCAST\n", prefix.c_str());
        break;
    case ndNETLINK_ATYPE_ERROR:
        nd_printf("%s: address is: ERROR!\n", prefix.c_str());
        break;
    default:
        nd_printf("%s: address is: Unhandled!\n", prefix.c_str());
        break;
    }
}

#ifndef _ND_USE_NETLINK_BSD

void ndNetlink::Refresh(void)
{
    int rc;
    struct nlmsghdr *nlh;

    memset(buffer, 0, buffer_length);

    nlh = (struct nlmsghdr *)buffer;

    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    nlh->nlmsg_type = RTM_GETROUTE;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_pid = 0;
    nlh->nlmsg_seq = seq++;

    if (send(nd, nlh, nlh->nlmsg_len, 0) < 0) {
        rc = errno;
        nd_printf("Error refreshing interface routes: %s\n", strerror(rc));
        throw ndNetlinkException(strerror(rc));
    }

    ProcessEvent();

    memset(buffer, 0, buffer_length);

    nlh = (struct nlmsghdr *)buffer;

    nlh->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifaddrmsg));
    nlh->nlmsg_type = RTM_GETADDR;
    nlh->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlh->nlmsg_pid = 0;
    nlh->nlmsg_seq = seq++;

    if (send(nd, nlh, nlh->nlmsg_len, 0) < 0) {
        rc = errno;
        nd_printf("Error refreshing interface addresses: %s\n", strerror(rc));
        throw ndNetlinkException(strerror(rc));
    }

    ProcessEvent();
}

bool ndNetlink::ProcessEvent(void)
{
    ssize_t bytes;
    struct nlmsghdr *nlh;
    struct nlmsgerr *nlerror;
    unsigned added_net = 0, removed_net = 0, added_addr = 0, removed_addr = 0;

    while ((bytes = recv(nd, buffer, buffer_length, 0)) > 0) {

        for (nlh = (struct nlmsghdr *)buffer;
            NLMSG_OK(nlh, bytes); nlh = NLMSG_NEXT(nlh, bytes)) {
#if 0
            nd_debug_printf(
                "NLMSG: %hu, len: %u (%u, %u), flags: 0x%x, seq: %u, pid: %u\n",
                nlh->nlmsg_type, nlh->nlmsg_len,
                NLMSG_HDRLEN, NLMSG_LENGTH(nlh->nlmsg_len),
                nlh->nlmsg_flags, nlh->nlmsg_seq, nlh->nlmsg_pid);
#endif
            switch(nlh->nlmsg_type) {
            case NLMSG_DONE:
                //nd_debug_printf("End of multi-part message.\n");
                break;
            case RTM_NEWROUTE:
                //nd_debug_printf("New route.\n");
                if (AddNetwork(nlh)) added_net++;
                break;
            case RTM_DELROUTE:
                //nd_debug_printf("Removed route.\n");
                if (RemoveNetwork(nlh)) removed_net++;
                break;
            case RTM_NEWADDR:
                //nd_debug_printf("New interface address.\n");
                if (AddAddress(nlh)) added_addr++;
                break;
            case RTM_DELADDR:
                //nd_debug_printf("Removed interface address.\n");
                if (RemoveAddress(nlh)) removed_addr++;
                break;
            case NLMSG_ERROR:
                nlerror = static_cast<struct nlmsgerr *>(NLMSG_DATA(nlh));
                if (nlerror->error != 0) {
                    nd_printf("Netlink error: %d\n", -nlerror->error);
                    return false;
                }
                break;
            case NLMSG_OVERRUN:
                nd_printf("Netlink overrun!\n");
                return false;
            default:
                nd_debug_printf("Ignored netlink message: %04x\n", nlh->nlmsg_type);
            }
        }
    }

    if (ND_DEBUG) {
        if (added_net || removed_net) {
            nd_debug_printf("Networks added: %d, removed: %d\n", added_net, removed_net);
        }
        if (added_addr || removed_addr) {
            nd_debug_printf("Addresses added: %d, removed: %d\n", added_addr, removed_addr);
        }

        if (added_net || removed_net || added_addr || removed_addr) Dump();
    }

    return (added_net || removed_net || added_addr || removed_addr) ? true : false;
}

#else // ! _ND_USE_NETLINK_BSD

void ndNetlink::Refresh(void)
{
    size_t length;
    if ((length = SysctlExecute(NET_RT_DUMP)) > 0)
        ProcessEvent(length);
    if ((length = SysctlExecute(NET_RT_IFLIST)) > 0)
        ProcessEvent(length);
}

#define _ND_NETLINK_SYSCTL_MIBS 6

size_t ndNetlink::SysctlExecute(int mode)
{
    size_t length = buffer_length;
    int mib[_ND_NETLINK_SYSCTL_MIBS] = {
        CTL_NET, AF_ROUTE, 0, AF_UNSPEC, mode, 0
    };

    if (sysctl(mib, _ND_NETLINK_SYSCTL_MIBS, NULL, &length, NULL, 0) < 0) {
        nd_printf("sysctl(%d): %s, %lu\n", mode, strerror(errno), length);
        return 0;
    }

    while (length > buffer_length) {
        buffer_length += _ND_NETLINK_BUFSIZ;
        buffer = (uint8_t *)realloc((void *)buffer, buffer_length);
        if (buffer == NULL) throw ndNetlinkException(strerror(ENOMEM));
    }

    if (sysctl(mib, _ND_NETLINK_SYSCTL_MIBS, buffer, &length, NULL, 0) < 0) {
        nd_printf("sysctl(%d): %s, %lu\n", mode, strerror(errno), length);
        return 0;
    }

    nd_debug_printf("sysctl(%d): returned %d bytes.\n", mode, length);

    return length;
}

bool ndNetlink::ProcessEvent(void)
{
    int rc = 0;
    ssize_t bytes;

    while ((bytes = recv(nd, buffer, buffer_length, 0)) > 0)
        rc += ProcessEvent(bytes);

    return (rc > 0);
}

bool ndNetlink::ProcessEvent(size_t length)
{
    struct rt_msghdr *rth;
    uint8_t *next, *limit = buffer + length;
    unsigned added_net = 0, removed_net = 0, added_addr = 0, removed_addr = 0;

    for (next = buffer; next < limit; next += rth->rtm_msglen) {
        rth = (struct rt_msghdr *)next;

        nd_debug_printf("%s: %ld [%hu:0x%02hhx:0x%02hhx]\n",
            __PRETTY_FUNCTION__, length,
            rth->rtm_msglen, rth->rtm_version, rth->rtm_type);

        switch (rth->rtm_type) {
        case RTM_ADD:
        case RTM_GET:
            nd_debug_printf("New route.\n");
            if (AddNetwork(rth)) added_net++;
            break;
        case RTM_DELETE:
            nd_debug_printf("Removed route.\n");
            if (RemoveNetwork(rth)) removed_net++;
            break;
        case RTM_NEWADDR:
            nd_debug_printf("Added interface address.\n");
            if (AddAddress((struct ifa_msghdr *)buffer)) added_addr++;
            break;
        case RTM_DELADDR:
            nd_debug_printf("Removed interface address.\n");
            if (RemoveAddress((struct ifa_msghdr *)buffer)) removed_addr++;
            break;
        default:
            nd_debug_printf("Ignored netlink message: %02hhx\n", rth->rtm_type);
        }
    }

    if (ND_DEBUG) {
        if (added_net || removed_net) {
            nd_debug_printf("Networks added: %d, removed: %d\n", added_net, removed_net);
        }
        if (added_addr || removed_addr) {
            nd_debug_printf("Addresses added: %d, removed: %d\n", added_addr, removed_addr);
        }

        if (added_net || removed_net || added_addr || removed_addr) Dump();
    }

    return (added_net || removed_net || added_addr || removed_addr) ? true : false;
}
#endif

ndNetlinkAddressType ndNetlink::ClassifyAddress(
    const struct sockaddr_storage *addr)
{
    ndNetlinkInterfaces::const_iterator iface;
    ndNetlinkAddressType type = ndNETLINK_ATYPE_UNKNOWN;

    for (iface = ifaces.begin();
        type == ndNETLINK_ATYPE_UNKNOWN &&
        iface != ifaces.end(); iface++) {
        type = ClassifyAddress(iface->first, addr);
    }

    vector<ndNetlinkNetworkAddr *>::const_iterator n;
    ndNetlinkNetworks::const_iterator net_list;

    vector<struct sockaddr_storage *>::const_iterator a;
    ndNetlinkAddresses::const_iterator addr_list;

    // Is addr a member of a multicast network?
    net_list = networks.find(_ND_NETLINK_MULTICAST);
    if (net_list == networks.end()) return ndNETLINK_ATYPE_ERROR;

    for (n = net_list->second.begin(); n != net_list->second.end(); n++) {

        if ((*n)->network.ss_family != addr->ss_family) continue;

        if (! InNetwork(
            (*n)->network.ss_family, (*n)->length, &(*n)->network, addr)) continue;

        type = ndNETLINK_ATYPE_MULTICAST;
        break;
    }

    if (type != ndNETLINK_ATYPE_UNKNOWN) return type;

    // Final guess: Is addr a member of a private (reserved/non-routable) network?
    net_list = networks.find(_ND_NETLINK_PRIVATE);
    if (net_list == networks.end()) return ndNETLINK_ATYPE_ERROR;

    for (n = net_list->second.begin(); n != net_list->second.end(); n++) {

        if ((*n)->network.ss_family != addr->ss_family) continue;

        if (! InNetwork(
            (*n)->network.ss_family, (*n)->length, &(*n)->network, addr)) continue;

        type = ndNETLINK_ATYPE_PRIVATE;
        break;
    }

    return type;
}

ndNetlinkAddressType ndNetlink::ClassifyAddress(
    const string &iface, const struct sockaddr_storage *addr)
{
    ndNetlinkAddressType type = ndNETLINK_ATYPE_UNKNOWN;

    ndNetlinkInterfaces::const_iterator lock = ifaces.find(iface);
    if (lock == ifaces.end()) return ndNETLINK_ATYPE_ERROR;

    // Paranoid AF_* check...
    if (addr->ss_family != AF_INET && addr->ss_family != AF_INET6) {
        nd_printf("WARNING: Address in unknown family: %hhu\n", addr->ss_family);
        return ndNETLINK_ATYPE_ERROR;
    }

    vector<ndNetlinkNetworkAddr *>::const_iterator n;
    ndNetlinkNetworks::const_iterator net_list;

    vector<struct sockaddr_storage *>::const_iterator a;
    ndNetlinkAddresses::const_iterator addr_list;

    // Is addr a broadcast address (IPv4 only)?
    if (addr->ss_family == AF_INET) {
        addr_list = addresses.find(_ND_NETLINK_BROADCAST);
        if (addr_list == addresses.end()) return ndNETLINK_ATYPE_ERROR;

        pthread_mutex_lock(lock->second);

        for (a = addr_list->second.begin(); a != addr_list->second.end(); a++) {

            if ((*a)->ss_family != addr->ss_family) continue;

            ndNetlinkNetworkAddr _addr1(addr), _addr2((*a));
            if (_addr1 != _addr2) continue;

            type = ndNETLINK_ATYPE_BROADCAST;
            break;
        }

        pthread_mutex_unlock(lock->second);
        if (type != ndNETLINK_ATYPE_UNKNOWN) return type;
    }

    // Is addr a local address to this interface?
    addr_list = addresses.find(iface);
    if (addr_list != addresses.end()) {

        pthread_mutex_lock(lock->second);

        for (a = addr_list->second.begin(); a != addr_list->second.end(); a++) {

            if ((*a)->ss_family != addr->ss_family) continue;

            ndNetlinkNetworkAddr _addr1(addr), _addr2((*a));
            if (_addr1 != _addr2) continue;

            type = ndNETLINK_ATYPE_LOCALIP;
            break;
        }

        pthread_mutex_unlock(lock->second);
    }
    if (type != ndNETLINK_ATYPE_UNKNOWN) return type;

    // Is addr a member of a local network to this interface?
    net_list = networks.find(iface);
    if (net_list != networks.end()) {

        pthread_mutex_lock(lock->second);

        for (n = net_list->second.begin(); n != net_list->second.end(); n++) {

            if ((*n)->network.ss_family != addr->ss_family) continue;

            if (! InNetwork(
                (*n)->network.ss_family, (*n)->length, &(*n)->network, addr)) continue;

            type = ndNETLINK_ATYPE_LOCALNET;
            break;
        }

        pthread_mutex_unlock(lock->second);
    }

    return type;
}

bool ndNetlink::InNetwork(sa_family_t family, uint8_t length,
    const struct sockaddr_storage *addr_net, const struct sockaddr_storage *addr_host)
{
    const struct sockaddr_in *ipv4_net, *ipv4_host;
    const  struct sockaddr_in6 *ipv6_net, *ipv6_host;
    int bit = (int)length, word, words;
    uint32_t i, word_net[4], word_host[4];

    switch (family) {
    case AF_INET:
        words = 1;

        ipv4_net = reinterpret_cast<const struct sockaddr_in *>(addr_net);
        word_net[0] = ntohl(ipv4_net->sin_addr.s_addr);

        ipv4_host = reinterpret_cast<const struct sockaddr_in *>(addr_host);
        word_host[0] = ntohl(ipv4_host->sin_addr.s_addr);
        break;

    case AF_INET6:
        words = 4;

        ipv6_net = reinterpret_cast<const struct sockaddr_in6 *>(addr_net);
        word_net[0] = ntohl(ipv6_net->sin6_addr.s6_addr32[0]);
        word_net[1] = ntohl(ipv6_net->sin6_addr.s6_addr32[1]);
        word_net[2] = ntohl(ipv6_net->sin6_addr.s6_addr32[2]);
        word_net[3] = ntohl(ipv6_net->sin6_addr.s6_addr32[3]);

        ipv6_host = reinterpret_cast<const struct sockaddr_in6 *>(addr_host);
        word_host[0] = ntohl(ipv6_host->sin6_addr.s6_addr32[0]);
        word_host[1] = ntohl(ipv6_host->sin6_addr.s6_addr32[1]);
        word_host[2] = ntohl(ipv6_host->sin6_addr.s6_addr32[2]);
        word_host[3] = ntohl(ipv6_host->sin6_addr.s6_addr32[3]);
        break;

    default:
        return false;
    }

    for (word = 0; word < words && bit > 0; word++) {
        for (i = 0x80000000; i > 0 && bit > 0; i >>= 1) {
            if ((word_host[word] & i) != (word_net[word] & i)) {
                return false;
            }
            bit--;
        }
    }

    return true;
}

bool ndNetlink::CopyNetlinkAddress(
        sa_family_t family, struct sockaddr_storage &dst, void *src)
{
    struct sockaddr_in *saddr_ip4;
    struct sockaddr_in6 *saddr_ip6;

    switch (family) {
    case AF_INET:
        saddr_ip4 = reinterpret_cast<struct sockaddr_in *>(&dst);
        memcpy(&saddr_ip4->sin_addr, src, sizeof(struct in_addr));
        dst.ss_family = family;
        return true;
    case AF_INET6:
        saddr_ip6 = reinterpret_cast<struct sockaddr_in6 *>(&dst);
        memcpy(&saddr_ip6->sin6_addr, src, sizeof(struct in6_addr));
        dst.ss_family = family;
        return true;
    }

    return false;
}

bool ndNetlink::AddInterface(const string &iface)
{
    ndNetlinkInterfaces::const_iterator i = ifaces.find(iface);
    if (i != ifaces.end()) return false;

    pthread_mutex_t *mutex = NULL;
    ND_NETLINK_DEVALLOC(mutex);
    ifaces[iface] = mutex;

    return true;
}

#ifndef _ND_USE_NETLINK_BSD

bool ndNetlink::ParseMessage(struct rtmsg *rtm, size_t offset,
    string &iface, ndNetlinkNetworkAddr &addr)
{
    char ifname[IFNAMSIZ];
    bool daddr_set = false;

    iface.clear();

    memset(&addr.network, 0, sizeof(struct sockaddr_storage));
    addr.length = 0;
    addr.network.ss_family = AF_UNSPEC;

    if (rtm->rtm_type != RTN_UNICAST) return false;

    switch (rtm->rtm_family) {
    case AF_INET:
        if (rtm->rtm_dst_len == 0 || rtm->rtm_dst_len == 32) return false;
        break;
    case AF_INET6:
        if (rtm->rtm_dst_len == 0 || rtm->rtm_dst_len == 128) return false;
        break;
    default:
        nd_debug_printf(
            "WARNING: Ignorning non-IPv4/6 route message: %04hx\n", rtm->rtm_family);
        return false;
    }

    addr.length = rtm->rtm_dst_len;

    for (struct rtattr *rta = static_cast<struct rtattr *>(RTM_RTA(rtm));
        RTA_OK(rta, offset); rta = RTA_NEXT(rta, offset)) {
        switch (rta->rta_type) {
            case RTA_UNSPEC:
                break;
            case RTA_DST:
                daddr_set = CopyNetlinkAddress(rtm->rtm_family, addr.network, RTA_DATA(rta));
                break;
            case RTA_OIF:
                if_indextoname(*(int *)RTA_DATA(rta), ifname);
                if (ifaces.find(ifname) == ifaces.end()) return false;
                iface.assign(ifname);
                break;
            default:
                break;
        }
    }

    if (daddr_set != true || iface.size() == 0) return false;

    return true;
}

bool ndNetlink::ParseMessage(struct ifaddrmsg *addrm, size_t offset,
    string &iface, struct sockaddr_storage &addr)
{
    bool addr_set = false;
    char ifname[IFNAMSIZ];
    struct sockaddr_storage addr_bcast;

    memset(&addr, 0, sizeof(struct sockaddr_storage));
    addr.ss_family = AF_UNSPEC;

    if_indextoname(addrm->ifa_index, ifname);
    if (ifaces.find(ifname) == ifaces.end()) return false;

    iface.assign(ifname);

    for (struct rtattr *rta = static_cast<struct rtattr *>(IFA_RTA(addrm));
        RTA_OK(rta, offset); rta = RTA_NEXT(rta, offset)) {
        switch (rta->rta_type) {
        case IFA_ADDRESS:
            addr_set = CopyNetlinkAddress(addrm->ifa_family, addr, RTA_DATA(rta));
            break;
        case IFA_LOCAL:
            addr_set = CopyNetlinkAddress(addrm->ifa_family, addr, RTA_DATA(rta));
            break;
        case IFA_BROADCAST:
            if (CopyNetlinkAddress(addrm->ifa_family, addr_bcast, RTA_DATA(rta)))
                AddAddress(_ND_NETLINK_BROADCAST, addr_bcast);
            break;
        }
    }

    return addr_set;
}

#else

bool ndNetlink::ParseMessage(struct rt_msghdr *rth, size_t offset,
    string &iface, ndNetlinkNetworkAddr &addr)
{
    char ifname[IFNAMSIZ];
    struct sockaddr *sa;

    memset(&addr.network, 0, sizeof(struct sockaddr_storage));
    addr.length = 0;
    addr.network.ss_family = AF_UNSPEC;

    iface.clear();

    if (if_indextoname(rth->rtm_index, ifname) == NULL) return false;
    if (ifaces.find(ifname) == ifaces.end()) return false;

    iface.assign(ifname);

    nd_debug_printf("%s: route address types: 0x%02x\n", ifname, rth->rtm_addrs);
    if (rth->rtm_addrs & RTA_DST == 0) {
        nd_debug_printf("%s: route: no destination address, skipping...\n", ifname);
        return false;
    }

    sa = (struct sockaddr *)(rth + 1);
    CopyNetlinkAddress(sa->sa_family, addr.network, sa);

    if (rth->rtm_addrs & RTA_GATEWAY)
        sa = _ND_NETLINK_NEXTSA(sa);

    if (rth->rtm_addrs & RTA_NETMASK == 0) {
        nd_debug_printf("%s: route: no netmask address, skipping...\n", ifname);
        return false;
    }

    addr.length = 24;

    return true;
}

bool ndNetlink::ParseMessage(struct ifa_msghdr *ifah, size_t offset,
    string &iface, struct sockaddr_storage &addr)
{
    char ifname[IFNAMSIZ];
    struct sockaddr *sa;

    iface.clear();

    if (if_indextoname(ifah->ifam_index, ifname) == NULL) return false;
    if (ifaces.find(ifname) == ifaces.end()) return false;

    iface.assign(ifname);

    nd_debug_printf("%s: interface address types: 0x%02x\n", ifname, ifah->ifam_addrs);

    return false;
}

#endif // ! _ND_USE_NETLINK_BSD

bool ndNetlink::AddNetwork(sa_family_t family,
    const string &type, const string &saddr, uint8_t length)
{
    ndNetlinkNetworkAddr *entry, addr;
    struct sockaddr_in *saddr_ip4;
    struct sockaddr_in6 *saddr_ip6;

    memset(&addr.network, 0, sizeof(struct sockaddr_storage));

    addr.length = length;
    addr.network.ss_family = family;
    saddr_ip4 = reinterpret_cast<struct sockaddr_in *>(&addr.network);
    saddr_ip6 = reinterpret_cast<struct sockaddr_in6 *>(&addr.network);

    switch (family) {
    case AF_INET:
        if (inet_pton(AF_INET, saddr.c_str(), &saddr_ip4->sin_addr) < 1)
            return false;
        break;
    case AF_INET6:
        if (inet_pton(AF_INET6, saddr.c_str(), &saddr_ip6->sin6_addr) < 1)
            return false;
        break;
    default:
        return false;
    }

    ND_NETLINK_NETALLOC(entry, addr);
    networks[type].push_back(entry);

    return true;
}

bool ndNetlink::AddAddress(
    sa_family_t family, const string &type, const string &saddr)
{
    struct sockaddr_storage *entry, addr;
    struct sockaddr_in *saddr_ip4;
    struct sockaddr_in6 *saddr_ip6;

    memset(&addr, 0, sizeof(struct sockaddr_storage));

    addr.ss_family = family;
    saddr_ip4 = reinterpret_cast<struct sockaddr_in *>(&addr);;
    saddr_ip6 = reinterpret_cast<struct sockaddr_in6 *>(&addr);;

    switch (family) {
    case AF_INET:
        if (inet_pton(AF_INET, saddr.c_str(), &saddr_ip4->sin_addr) < 0)
            return false;
        break;
    case AF_INET6:
        if (inet_pton(AF_INET6, saddr.c_str(), &saddr_ip6->sin6_addr) < 0)
            return false;
        break;
    default:
        return false;
    }

    ND_NETLINK_ADDRALLOC(entry, addr);
    addresses[type].push_back(entry);

    return true;
}

bool ndNetlink::AddAddress(const string &type,
    const struct sockaddr_storage &addr)
{
    struct sockaddr_storage *entry;

    ndNetlinkInterfaces::const_iterator lock = ifaces.find(type);
    if (lock == ifaces.end()) return false;

    pthread_mutex_lock(lock->second);
    ND_NETLINK_ADDRALLOC(entry, addr);
    addresses[type].push_back(entry);
    pthread_mutex_unlock(lock->second);

    return true;
}

#ifndef _ND_USE_NETLINK_BSD

bool ndNetlink::AddNetwork(struct nlmsghdr *nlh)
{
    string iface;
    ndNetlinkNetworkAddr addr;

    if (ParseMessage(
        static_cast<struct rtmsg *>(NLMSG_DATA(nlh)),
        RTM_PAYLOAD(nlh), iface, addr) == false) return false;

    ndNetlinkNetworks::const_iterator i = networks.find(iface);
    if (i != networks.end()) {
        for (vector<ndNetlinkNetworkAddr *>::const_iterator j = i->second.begin();
            j != i->second.end(); j++) {
            if (*(*j) == addr) return false;
        }
    }

    ndNetlinkInterfaces::const_iterator lock = ifaces.find(iface);
    if (lock == ifaces.end()) return false;

    ndNetlinkNetworkAddr *entry;
    ND_NETLINK_NETALLOC(entry, addr);

    pthread_mutex_lock(lock->second);
    networks[iface].push_back(entry);
    pthread_mutex_unlock(lock->second);

    return true;
}

bool ndNetlink::RemoveNetwork(struct nlmsghdr *nlh)
{
    string iface;
    ndNetlinkNetworkAddr addr;
    bool removed = false;

    if (ParseMessage(
        static_cast<struct rtmsg *>(NLMSG_DATA(nlh)),
        RTM_PAYLOAD(nlh), iface, addr) == false) {
        //nd_debug_printf("Remove network parse error\n");
        return false;
    }

    ndNetlinkNetworks::iterator i = networks.find(iface);
    if (i == networks.end()) {
        nd_debug_printf("WARNING: Couldn't find interface in networks map: %s\n",
            iface.c_str());
        return false;
    }

    ndNetlinkInterfaces::const_iterator lock = ifaces.find(iface);
    if (lock == ifaces.end()) return false;

    pthread_mutex_lock(lock->second);

    for (vector<ndNetlinkNetworkAddr *>::iterator j = i->second.begin();
        j != i->second.end(); j++) {
        if (*(*j) == addr) {
            i->second.erase(j);
            removed = true;
            break;
        }
    }

    pthread_mutex_unlock(lock->second);

    return removed;
}

bool ndNetlink::AddAddress(struct nlmsghdr *nlh)
{
    string iface;
    struct sockaddr_storage addr;

    if (ParseMessage(
        static_cast<struct ifaddrmsg *>(NLMSG_DATA(nlh)),
        IFA_PAYLOAD(nlh), iface, addr) == false) return false;

    ndNetlinkAddresses::const_iterator i = addresses.find(iface);
    if (i != addresses.end()) {
        for (vector<struct sockaddr_storage *>::const_iterator j = i->second.begin();
            j != i->second.end(); j++) {
            if (memcmp((*j), &addr, sizeof(struct sockaddr_storage)) == 0)
                return false;
        }
    }

    ndNetlinkInterfaces::const_iterator lock = ifaces.find(iface);
    if (lock == ifaces.end()) return false;

    struct sockaddr_storage *entry;
    ND_NETLINK_ADDRALLOC(entry, addr);

    pthread_mutex_lock(lock->second);
    addresses[iface].push_back(entry);
    pthread_mutex_unlock(lock->second);

    return true;
}

bool ndNetlink::RemoveAddress(struct nlmsghdr *nlh)
{
    string iface;
    struct sockaddr_storage addr;
    bool removed = false;

    if (ParseMessage(
        static_cast<struct ifaddrmsg *>(NLMSG_DATA(nlh)),
        IFA_PAYLOAD(nlh), iface, addr) == false) return false;

    ndNetlinkAddresses::iterator i = addresses.find(iface);
    if (i == addresses.end()) {
        nd_debug_printf("WARNING: Couldn't find interface in addresses map: %s\n",
            iface.c_str());
        return false;
    }

    ndNetlinkInterfaces::const_iterator lock = ifaces.find(iface);
    if (lock == ifaces.end()) return false;

    pthread_mutex_lock(lock->second);

    for (vector<struct sockaddr_storage *>::iterator j = i->second.begin();
        j != i->second.end(); j++) {
        if (memcmp((*j), &addr, sizeof(struct sockaddr_storage)) == 0) {
            i->second.erase(j);
            removed = true;
            break;
        }
    }

    pthread_mutex_unlock(lock->second);

    return removed;
}

#else

bool ndNetlink::AddNetwork(struct rt_msghdr *rth)
{
    string iface;
    ndNetlinkNetworkAddr addr;

    if (ParseMessage(rth, 0, iface, addr) == false) return false;

    ndNetlinkNetworks::const_iterator i = networks.find(iface);
    if (i != networks.end()) {
        for (vector<ndNetlinkNetworkAddr *>::const_iterator j = i->second.begin();
            j != i->second.end(); j++) {
            if (*(*j) == addr) return false;
        }
    }

    ndNetlinkInterfaces::const_iterator lock = ifaces.find(iface);
    if (lock == ifaces.end()) return false;

    ndNetlinkNetworkAddr *entry;
    ND_NETLINK_NETALLOC(entry, addr);

    pthread_mutex_lock(lock->second);
    networks[iface].push_back(entry);
    pthread_mutex_unlock(lock->second);

    return true;
}

bool ndNetlink::RemoveNetwork(struct rt_msghdr *rth)
{
    string iface;
    ndNetlinkNetworkAddr addr;
    bool removed = false;

    if (ParseMessage(rth, 0, iface, addr) == false)
        return false;

    ndNetlinkNetworks::iterator i = networks.find(iface);
    if (i == networks.end()) {
        nd_debug_printf("WARNING: Couldn't find interface in networks map: %s\n",
            iface.c_str());
        return false;
    }

    ndNetlinkInterfaces::const_iterator lock = ifaces.find(iface);
    if (lock == ifaces.end()) return false;

    pthread_mutex_lock(lock->second);

    for (vector<ndNetlinkNetworkAddr *>::iterator j = i->second.begin();
        j != i->second.end(); j++) {
        if (*(*j) == addr) {
            i->second.erase(j);
            removed = true;
            break;
        }
    }

    pthread_mutex_unlock(lock->second);

    return removed;
}

bool ndNetlink::AddAddress(struct ifa_msghdr *ifah)
{
    string iface;
    struct sockaddr_storage addr;

    if (ParseMessage(ifah, 0, iface, addr) == false) return false;

    ndNetlinkAddresses::const_iterator i = addresses.find(iface);
    if (i != addresses.end()) {
        for (vector<struct sockaddr_storage *>::const_iterator j = i->second.begin();
            j != i->second.end(); j++) {
            if (memcmp((*j), &addr, sizeof(struct sockaddr_storage)) == 0)
                return false;
        }
    }

    ndNetlinkInterfaces::const_iterator lock = ifaces.find(iface);
    if (lock == ifaces.end()) return false;

    struct sockaddr_storage *entry;
    ND_NETLINK_ADDRALLOC(entry, addr);

    pthread_mutex_lock(lock->second);
    addresses[iface].push_back(entry);
    pthread_mutex_unlock(lock->second);

    return true;
}

bool ndNetlink::RemoveAddress(struct ifa_msghdr *ifah)
{
    string iface;
    struct sockaddr_storage addr;
    bool removed = false;

    if (ParseMessage(ifah, 0, iface, addr) == false) return false;

    ndNetlinkAddresses::iterator i = addresses.find(iface);
    if (i == addresses.end()) {
        nd_debug_printf("WARNING: Couldn't find interface in addresses map: %s\n",
            iface.c_str());
        return false;
    }

    ndNetlinkInterfaces::const_iterator lock = ifaces.find(iface);
    if (lock == ifaces.end()) return false;

    pthread_mutex_lock(lock->second);

    for (vector<struct sockaddr_storage *>::iterator j = i->second.begin();
        j != i->second.end(); j++) {
        if (memcmp((*j), &addr, sizeof(struct sockaddr_storage)) == 0) {
            i->second.erase(j);
            removed = true;
            break;
        }
    }

    pthread_mutex_unlock(lock->second);

    return removed;
}

#endif // ! _ND_USE_NETLINK_BSD

void ndNetlink::Dump(void)
{
    for (ndNetlinkNetworks::iterator i = networks.begin();
        i != networks.end(); i++) {
        for (vector<ndNetlinkNetworkAddr *>::iterator j = i->second.begin();
            j != i->second.end(); j++) {
            nd_printf("%s: net ", i->first.c_str());
            nd_print_address(&(*j)->network);
            nd_printf("/%hhu\n", (*j)->length);
        }
    }

    for (ndNetlinkAddresses::iterator i = addresses.begin();
        i != addresses.end(); i++) {
        for (vector<struct sockaddr_storage *>::iterator j = i->second.begin();
            j != i->second.end(); j++) {
            nd_printf("%s: addr ", i->first.c_str());
            nd_print_address((*j));
            nd_printf("\n");
        }
    }
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
