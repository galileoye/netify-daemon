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
#include <cerrno>
#include <cstring>
#include <deque>
#include <iostream>
#include <map>
#include <queue>
#include <sstream>
#include <stdexcept>
#include <string>
#include <unordered_map>
#include <vector>
#include <atomic>

#include <arpa/inet.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <netdb.h>
#include <net/if.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <pthread.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/un.h>

#include <pcap/pcap.h>

#include <json.h>

#if defined (_ND_USE_NETLINK) && defined(HAVE_LINUX_NETLINK_H)
#include <linux/netlink.h>
#endif

#ifdef _ND_USE_CONNTRACK
#include <libnetfilter_conntrack/libnetfilter_conntrack.h>
#endif

#include "ndpi_main.h"

using namespace std;

#ifndef UNIX_PATH_MAX
#define UNIX_PATH_MAX 108
#endif

#include "netifyd.h"
#include "nd-util.h"
#ifdef _ND_USE_NETLINK
#include "nd-netlink.h"
#endif
#include "nd-json.h"
#include "nd-flow.h"
#include "nd-thread.h"
#ifdef _ND_USE_CONNTRACK
#include "nd-conntrack.h"
#endif
#include "nd-socket.h"

#define _ND_SOCKET_PROC_NET_UNIX    "/proc/net/unix"

extern nd_global_config nd_config;

ndSocketLocal::ndSocketLocal(ndSocket *base, const string &node)
    : base(base), valid(false)
{
    //nd_debug_printf("%s\n", __PRETTY_FUNCTION__);
    struct sockaddr_un *sa_un = new struct sockaddr_un;

    base->node = node;
    base->sa_size = sizeof(struct sockaddr_un);
    base->sa = (sockaddr *)sa_un;

    memset(sa_un, 0, base->sa_size);

    sa_un->sun_family = base->family = AF_LOCAL;
    strncpy(sa_un->sun_path, base->node.c_str(), UNIX_PATH_MAX);

    int rc;

    if ((rc = IsValid()) != 0)
        throw ndSocketSystemException(__PRETTY_FUNCTION__, node, rc);

    valid = true;

    base->Create();
}

ndSocketLocal::~ndSocketLocal()
{
    //nd_debug_printf("%s\n", __PRETTY_FUNCTION__);
    if (valid && base->type == ndSOCKET_TYPE_SERVER)
        unlink(base->node.c_str());
}

int ndSocketLocal::IsValid(void)
{
    //nd_debug_printf("%s\n", __PRETTY_FUNCTION__);

    struct stat socket_stat;

    if (base->type == ndSOCKET_TYPE_CLIENT) {
        stat(base->node.c_str(), &socket_stat);
        return errno;
    }
    else if (base->type == ndSOCKET_TYPE_SERVER) {
        int rc = 0;
        long max_path_len = 4096;

        max_path_len = pathconf(base->node.c_str(), _PC_PATH_MAX);
        if (max_path_len == -1) return errno;

        FILE *fh = fopen(_ND_SOCKET_PROC_NET_UNIX, "r");
        if (! fh) return errno;

        for ( ;; ) {
            char filename[max_path_len];
            unsigned int a, b, c, d, e, f, g;
            int count = fscanf(fh, "%x: %u %u %u %u %u %u ",
                &a, &b, &c, &d, &e, &f, &g);
            if (count == 0) {
                if (! fgets(filename, max_path_len, fh)) break;
                continue;
            }
            else if (count == -1) break;
            else if (! fgets(filename, max_path_len, fh)) break;
            else if (strncmp(filename, base->node.c_str(), base->node.size()) == 0) {
                rc = EADDRINUSE;
                break;
            }
        }

        fclose(fh);

        if (rc != 0) return rc;

        if (stat(base->node.c_str(), &socket_stat) != 0 && errno != ENOENT)
            return errno;

        unlink(base->node.c_str());
    }

    return 0;
}

ndSocketRemote::ndSocketRemote(
    ndSocket *base, const string &node, const string &service)
    : base(base)
{
    //nd_debug_printf("%s\n", __PRETTY_FUNCTION__);

    base->node = node;
    base->service = service;

    base->Create();
}

ndSocketRemote::~ndSocketRemote()
{
    //nd_debug_printf("%s\n", __PRETTY_FUNCTION__);
}

ndSocketClient::ndSocketClient(ndSocket *base)
    : base(base)
{
    //nd_debug_printf("%s\n", __PRETTY_FUNCTION__);

    base->type = ndSOCKET_TYPE_CLIENT;
}

ndSocketClient::~ndSocketClient()
{
}

ndSocket *ndSocketServer::Accept(void)
{
    //nd_debug_printf("%s\n", __PRETTY_FUNCTION__);
    ndSocket *peer = NULL;
    int peer_sd = -1;
    socklen_t peer_sa_size = 0;
    sockaddr *peer_sa = NULL;

    if (base->sa_size == sizeof(struct sockaddr_un)) {
        peer_sa = (sockaddr *)new struct sockaddr_un;
        peer_sa_size = sizeof(struct sockaddr_un);
    }
    else {
        peer_sa = (sockaddr *)new struct sockaddr_storage;
        peer_sa_size = sizeof(struct sockaddr_storage);
    }

    if (peer_sa == NULL)
        throw ndSocketSystemException(__PRETTY_FUNCTION__, "new", ENOMEM);

    try {
        peer_sd = accept(base->sd, peer_sa, &peer_sa_size);
        if (peer_sd < 0)
            throw ndSocketSystemException(__PRETTY_FUNCTION__, "accept", errno);

        if (base->sa_size == sizeof(struct sockaddr_un)) {
            peer = new ndSocket(base->node);
            if (peer == NULL)
                throw ndSocketSystemException(__PRETTY_FUNCTION__, "new", ENOMEM);

            nd_debug_printf("%s: peer: %s\n", __PRETTY_FUNCTION__, base->node.c_str());
        }
        else {
            char node[NI_MAXHOST], service[NI_MAXSERV];

            int rc = getnameinfo(peer_sa, peer_sa_size, node, NI_MAXHOST,
                service, NI_MAXSERV, NI_NUMERICHOST | NI_NUMERICSERV);

            if (rc != 0) {
                throw ndSocketGetAddrInfoException(
                    __PRETTY_FUNCTION__, "getnameinfo", rc);
            }

            peer = new ndSocket(node, service);
            if (peer == NULL)
                throw ndSocketSystemException(__PRETTY_FUNCTION__, "new", ENOMEM);

            nd_debug_printf("%s: peer: %s:%s\n", __PRETTY_FUNCTION__, node, service);
        }

        peer->sd = peer_sd;
        peer->family = base->family;
        peer->type = ndSOCKET_TYPE_CLIENT;
        peer->state = ndSOCKET_STATE_ACCEPTED;

        delete (peer_sa);
    }
    catch (runtime_error &e) {
        if (peer != NULL) {
            delete peer;
            peer = NULL;
        }
        else if (peer_sa != NULL)
            delete peer_sa;
        if (peer_sd >= 0) close(peer_sd);
        throw;
    }

    return peer;
}

ndSocketServer::ndSocketServer(ndSocket *base)
    : base(base)
{
    //nd_debug_printf("%s\n", __PRETTY_FUNCTION__);
    base->type = ndSOCKET_TYPE_SERVER;
}

ndSocketServer::~ndSocketServer()
{
    //nd_debug_printf("%s\n", __PRETTY_FUNCTION__);
}

ndSocketClientLocal::ndSocketClientLocal(const string &node)
    : ndSocketClient(this), ndSocketLocal(this, node)
{
    //nd_debug_printf("%s\n", __PRETTY_FUNCTION__);

}

ndSocketClientLocal::~ndSocketClientLocal()
{
    //nd_debug_printf("%s\n", __PRETTY_FUNCTION__);
}

ndSocketServerLocal::ndSocketServerLocal(const string &node)
    : ndSocketServer(this), ndSocketLocal(this, node)
{
    //nd_debug_printf("%s\n", __PRETTY_FUNCTION__);
}

ndSocketServerLocal::~ndSocketServerLocal()
{
    //nd_debug_printf("%s\n", __PRETTY_FUNCTION__);
}

ndSocketClientRemote::ndSocketClientRemote(const string &node, const string &service)
    : ndSocketClient(this), ndSocketRemote(this, node, service)
{
    //nd_debug_printf("%s\n", __PRETTY_FUNCTION__);
}

ndSocketClientRemote::~ndSocketClientRemote()
{
    //nd_debug_printf("%s\n", __PRETTY_FUNCTION__);
}

ndSocketServerRemote::ndSocketServerRemote(const string &node, const string &service)
    : ndSocketServer(this), ndSocketRemote(this, node, service)
{
    //nd_debug_printf("%s\n", __PRETTY_FUNCTION__);
}

ndSocketServerRemote::~ndSocketServerRemote()
{
    //nd_debug_printf("%s\n", __PRETTY_FUNCTION__);
}

ndSocket::ndSocket()
    : sd(1), family(AF_UNSPEC), sa(NULL), sa_size(0),
    type(ndSOCKET_TYPE_NULL), state(ndSOCKET_STATE_INIT),
    bytes_in(0), bytes_out(0)
{
    //nd_debug_printf("%s\n", __PRETTY_FUNCTION__);
}

ndSocket::ndSocket(const string &node)
    : sd(-1), family(AF_UNSPEC), sa(NULL), sa_size(0),
    node(node), type(ndSOCKET_TYPE_NULL), state(ndSOCKET_STATE_INIT),
    bytes_in(0), bytes_out(0)
{
    //nd_debug_printf("%s\n", __PRETTY_FUNCTION__);
}

ndSocket::ndSocket(const string &host, const string &service)
    : sd(-1), family(AF_UNSPEC), sa(NULL), sa_size(0),
    node(host), service(service),
    type(ndSOCKET_TYPE_NULL), state(ndSOCKET_STATE_INIT),
    bytes_in(0), bytes_out(0)
{
    //nd_debug_printf("%s\n", __PRETTY_FUNCTION__);
}

ndSocket::~ndSocket()
{
    //nd_debug_printf("%s\n", __PRETTY_FUNCTION__);
    if (sd != -1) close(sd);
    if (sa != NULL) delete sa;
}

ssize_t ndSocket::Read(uint8_t *buffer, ssize_t length)
{
    uint8_t *p = buffer;
    ssize_t bytes_read = 0, bytes_remaining = length;

    //nd_debug_printf("%s\n", __PRETTY_FUNCTION__);

    do {
        ssize_t rc = read(sd, p, bytes_remaining);

        if (rc < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK)
                throw ndSocketSystemException(__PRETTY_FUNCTION__, "read", errno);
            break;
        }

        if (rc == 0)
            throw ndSocketHangupException("read");

        bytes_read += rc;
        p += rc;
        bytes_remaining -= rc;
        bytes_in += rc;
    } while (bytes_remaining > 0);

    return bytes_read;
}

ssize_t ndSocket::Write(const uint8_t *buffer, ssize_t length)
{
    const uint8_t *p = buffer;
    ssize_t bytes_wrote = 0, bytes_remaining = length;

    //nd_debug_printf("%s\n", __PRETTY_FUNCTION__);

    do {
        ssize_t rc = write(sd, p, bytes_remaining);

        if (rc < 0) {
            if (errno != EAGAIN && errno != EWOULDBLOCK)
                throw ndSocketSystemException(__PRETTY_FUNCTION__, "write", errno);
            break;
        }

        if (rc == 0)
            throw ndSocketHangupException("write");

        bytes_wrote += rc;
        p += rc;
        bytes_remaining -= rc;
        bytes_out += rc;
    } while (bytes_remaining > 0);

    return bytes_wrote;
}

void ndSocket::SetBlockingMode(bool enable)
{
    int flags;

    //nd_debug_printf("%s\n", __PRETTY_FUNCTION__);

    if (enable == false) {
        flags = fcntl(sd, F_GETFL);
        if (fcntl(sd, F_SETFL, flags | O_NONBLOCK) < 0) {
            throw ndSocketSystemException(
                __PRETTY_FUNCTION__, "fcntl: O_NONBLOCK", errno);
        }
    }
    else {
        flags = fcntl(sd, F_GETFL);
        flags &= ~O_NONBLOCK;
        if (fcntl(sd, F_SETFL, flags) < 0) {
            throw ndSocketSystemException(
                __PRETTY_FUNCTION__, "fcntl: O_NONBLOCK", errno);
        }
    }
}

void ndSocket::Create(void)
{
    //nd_debug_printf("%s\n", __PRETTY_FUNCTION__);

    if (family == AF_UNSPEC) {
        struct addrinfo hints;
        struct addrinfo *result, *rp;

        memset(&hints, 0, sizeof(struct addrinfo));
        hints.ai_family = AF_INET6;
        //hints.ai_family = AF_UNSPEC;
        hints.ai_socktype = SOCK_STREAM;
        hints.ai_flags = AI_V4MAPPED;
        //hints.ai_flags = AI_V4MAPPED | AI_ALL;
        if (type == ndSOCKET_TYPE_SERVER)
            hints.ai_flags |= AI_PASSIVE;
        hints.ai_protocol = IPPROTO_TCP;
        hints.ai_canonname = NULL;
        hints.ai_addr = NULL;
        hints.ai_next = NULL;

        int rc;
        const char *_node = (node.length()) ? node.c_str() : NULL;
        if ((rc = getaddrinfo(_node, service.c_str(), &hints, &result)) != 0) {
            throw ndSocketGetAddrInfoException(
                __PRETTY_FUNCTION__, "getaddrinfo", rc);
        }

        sd = -1;
        for (rp = result; rp != NULL; rp = rp->ai_next) {
            sd = socket(rp->ai_family,
                rp->ai_socktype | SOCK_NONBLOCK, rp->ai_protocol);
            if (sd < 0) {
                nd_printf("%s: socket: %s",
                    __PRETTY_FUNCTION__, strerror(errno));
                continue;
            }

            if (type == ndSOCKET_TYPE_CLIENT) {
                if (connect(sd, rp->ai_addr, rp->ai_addrlen) == 0) {
                    nd_printf("%s: connected\n", __PRETTY_FUNCTION__);
                    break;
                }
                else {
                    if (rp->ai_family == AF_INET) {
                        nd_printf("%s: connect v4: %s\n",
                            __PRETTY_FUNCTION__, strerror(errno));
                    }
                    else if (rp->ai_family == AF_INET6) {
                        nd_printf("%s: connect v6: %s\n",
                            __PRETTY_FUNCTION__, strerror(errno));
                    }
                    else {
                        nd_printf("%s: connect: %s\n",
                            __PRETTY_FUNCTION__, strerror(errno));
                    }
                }
            }
            else if (type == ndSOCKET_TYPE_SERVER) {
                int on = 1;
                if (setsockopt(sd,
                    SOL_SOCKET, SO_REUSEADDR, (char *)&on, sizeof(on)) != 0) {
                    throw ndSocketSystemException(__PRETTY_FUNCTION__,
                        "setsockopt: SO_REUSEADDR", errno);
                }

                if (bind(sd, rp->ai_addr, rp->ai_addrlen) == 0) break;
                else {
                    nd_printf("%s: bind: %s\n",
                        __PRETTY_FUNCTION__, strerror(errno));
                }
            }

            close(sd); sd = -1;
        }

        if (rp == NULL) {
            freeaddrinfo(result);
            throw ndSocketException(__PRETTY_FUNCTION__, "no addresses found");
        }

        family = rp->ai_family;
        sa_size = rp->ai_addrlen;
        sa = (sockaddr *)new uint8_t[sa_size];
        memcpy(sa, rp->ai_addr, sa_size);

        freeaddrinfo(result);

        if (sd < 0) {
            throw ndSocketException(__PRETTY_FUNCTION__, "unable to create socket");
        }

        if (type == ndSOCKET_TYPE_SERVER) {
            if (listen(sd, SOMAXCONN) != 0)
                throw ndSocketSystemException(__PRETTY_FUNCTION__, "listen", errno);
        }
    }
    else if (family == AF_LOCAL) {
        if ((sd = socket(family, SOCK_STREAM | SOCK_NONBLOCK, 0)) < 0)
            throw ndSocketSystemException(__PRETTY_FUNCTION__, "socket", errno);

        if (type == ndSOCKET_TYPE_CLIENT) {
            if (connect(sd, sa, sa_size) != 0)
                throw ndSocketSystemException(__PRETTY_FUNCTION__, "connect", errno);
            nd_printf("%s: connected\n", __PRETTY_FUNCTION__);
        }
        else if (type == ndSOCKET_TYPE_SERVER) {
            if (bind(sd, sa, sa_size) != 0)
                throw ndSocketSystemException(__PRETTY_FUNCTION__, "bind", errno);

            if (listen(sd, SOMAXCONN) != 0)
                throw ndSocketSystemException(__PRETTY_FUNCTION__, "listen", errno);
        }
    }

    nd_debug_printf("%s: created\n", __PRETTY_FUNCTION__);
}

size_t ndSocketBuffer::GetLength(void)
{
    if (buffer.size() == 0) return 0;
    return length - offset;
}

const uint8_t *ndSocketBuffer::GetBuffer(ssize_t &length)
{
    if (buffer.size() == 0) {
        length = 0;
        return NULL;
    }

    length = buffer.front().size() - offset;
    return (const uint8_t *)(buffer.front().c_str() + offset);
}

void ndSocketBuffer::Push(const string &data)
{
    ostringstream header;
    header << "{\"length\": " << data.size() << "}\n";
    buffer.push_back(header.str());
    buffer.push_back(data);
    length += data.size();
}

void ndSocketBuffer::Pop(ssize_t length)
{
    if (length <= 0 || buffer.size() == 0) return;
    size_t bytes = buffer.front().size() - offset;
    if (bytes <= 0) return;
    if ((size_t)length > bytes) return;
    if ((size_t)length == bytes) {
        offset = 0;
        buffer.pop_front();
    }
    else if ((size_t)length < bytes)
        offset += length;

    length -= bytes;
}

ndSocketThread::ndSocketThread()
    : ndThread("nd-socket", -1), terminate(false)
{
    vector<pair<string, string> >::const_iterator i;
    for (i = nd_config.socket_host.begin();
        i != nd_config.socket_host.end(); i++) {
        ndSocketServerRemote *skt;
        skt = new ndSocketServerRemote((*i).first, (*i).second);
        skt->SetBlockingMode(false);
        servers[skt->GetDescriptor()] = skt;
    }
    vector<string>::const_iterator j;
    for (j = nd_config.socket_path.begin();
        j != nd_config.socket_path.end(); j++) {
        ndSocketServerLocal *skt;
        skt = new ndSocketServerLocal((*j));
        skt->SetBlockingMode(false);
        servers[skt->GetDescriptor()] = skt;
    }
}

ndSocketThread::~ndSocketThread()
{
    Join();

    for (ndSocketMap::const_iterator i = clients.begin();
        i != clients.end(); i++) {
        delete i->second;
    }
    for (ndSocketServerMap::const_iterator i = servers.begin();
        i != servers.end(); i++) {
        delete reinterpret_cast<ndSocket *>(i->second);
    }
    for (ndSocketBufferMap::const_iterator i = buffers.begin();
        i != buffers.end(); i++) {
        delete i->second;
    }
}

void ndSocketThread::QueueWrite(const string &data)
{
    Lock();
    queue_write.push_back(data);
    Unlock();
}

void ndSocketThread::ClientAccept(ndSocketServerMap::iterator &si)
{
    ndSocket *client = NULL;
    ndSocketBuffer *buffer = NULL;

    try {
        buffer = new ndSocketBuffer();
        if (buffer == NULL)
            throw ndSocketThreadException(__PRETTY_FUNCTION__, "new", ENOMEM);

        client = si->second->Accept();
    } catch (ndSocketGetAddrInfoException &e) {
        if (client) delete client;
        throw;
    } catch (ndSocketSystemException &e) {
        if (client) delete client;
        throw;
    }

    buffers[client->GetDescriptor()] = buffer;
    clients[client->GetDescriptor()] = client;

    string json_protos;
    nd_json_protocols(json_protos);
    buffer->Push(json_protos);
}

void ndSocketThread::ClientHangup(ndSocketMap::iterator &ci)
{
    ndSocketBufferMap::iterator bi;

    nd_printf("%s\n", __PRETTY_FUNCTION__);

    delete ci->second;
    bi = buffers.find(ci->first);
    clients.erase(ci++);

    if (bi == buffers.end()) {
        throw ndSocketThreadException(
            __PRETTY_FUNCTION__, "buffers.find", ENOENT);
    }
    else {
        delete bi->second;
        buffers.erase(bi);
    }
}

void *ndSocketThread::Entry(void)
{
    int rc, max_fd;
    fd_set fds_read, fds_write;
    struct timeval tv;
    ndSocketMap::iterator ci;
    ndSocketServerMap::iterator si;
    ndSocketBufferMap::iterator bi;

    nd_debug_printf("%s: started\n", __PRETTY_FUNCTION__);

    while (! terminate) {
        max_fd = -1;

        FD_ZERO(&fds_read);
        FD_ZERO(&fds_write);

        Lock();
        if (queue_write.size()) {
            for (vector<string>::iterator i = queue_write.begin();
                i != queue_write.end(); i++) {
                for (bi = buffers.begin(); bi != buffers.end(); bi++)
                    bi->second->Push((*i));
            }
            queue_write.clear();
        }
        Unlock();

        for (ci = clients.begin(); ci != clients.end(); ci++) {

            FD_SET(ci->first, &fds_read);
            if (ci->first > max_fd) max_fd = ci->first;

            bi = buffers.find(ci->first);
            if (bi == buffers.end()) {
                throw ndSocketThreadException(
                    __PRETTY_FUNCTION__, "buffers.find", ENOENT);
            }

            if (bi->second->GetLength() > 0)
                FD_SET(ci->first, &fds_write);
        }

        for (si = servers.begin(); si != servers.end(); si++) {

            FD_SET(si->first, &fds_read);
            if (si->first > max_fd) max_fd = si->first;
        }

        memset(&tv, 0, sizeof(struct timeval));
        tv.tv_sec = 1;

        rc = select(max_fd + 1, &fds_read, &fds_write, NULL, &tv);

        if (rc == -1 && errno != EINTR) {
            throw ndSocketThreadException(
                __PRETTY_FUNCTION__, "select", errno);
        }

        if (rc == 0) continue;

        ci = clients.begin();

        while (ci != clients.end()) {

            if (FD_ISSET(ci->first, &fds_read)) {
                ClientHangup(ci);
                if (--rc == 0) break;
                continue;
            }

            if (FD_ISSET(ci->first, &fds_write)) {

                bi = buffers.find(ci->first);
                if (bi == buffers.end()) {
                    throw ndSocketThreadException(__PRETTY_FUNCTION__,
                        "buffers.find", ENOENT);
                }

                ssize_t length;
                const uint8_t *p = bi->second->GetBuffer(length);

                try {
                    ssize_t bytes = ci->second->Write(p, length);
                    bi->second->Pop(bytes);
                } catch (ndSocketHangupException &e) {
                    ClientHangup(ci);
                } catch (ndSocketSystemException &e) {
                    ClientHangup(ci);
                }

                if (--rc == 0) break;
                continue;
            }

            ci++;
        }

        if (rc == 0) continue;

        for (si = servers.begin(); si != servers.end(); si++) {
            if (FD_ISSET(si->first, &fds_read)) {
                try {
                    ClientAccept(si);
                } catch (runtime_error &e) {
                    nd_printf("%s: Error accepting socket connection: %s\n",
                        tag.c_str(), e.what());
                }

                if (--rc == 0) break;
            }
        }
    }

    terminated = true;

    return NULL;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
