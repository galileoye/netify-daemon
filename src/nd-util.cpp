// Netify Daemon
// Copyright (C) 2015-2017 eGloo Incorporated <http://www.egloo.ca>
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

#include <stdexcept>
#include <cstdlib>
#include <cstdarg>
#include <string>
#include <sstream>

#include <unistd.h>
#include <syslog.h>
#include <fcntl.h>
#include <errno.h>

#include <sys/resource.h>
#include <sys/socket.h>

#include <netdb.h>

#include "ndpi_main.h"

using namespace std;

#include "nd-util.h"
#include "nd-sha1.h"

extern bool nd_debug;

void *nd_mem_alloc(size_t size)
{
    return malloc(size);
}

void nd_mem_free(void *ptr)
{
    free(ptr);
}

extern pthread_mutex_t *nd_output_mutex;

void nd_printf(const char *format, ...)
{
    pthread_mutex_lock(nd_output_mutex);

    va_list ap;
    va_start(ap, format);

    if (nd_debug)
        vfprintf(stdout, format, ap);
    else
        vsyslog(LOG_DAEMON | LOG_INFO, format, ap);

    va_end(ap);

    pthread_mutex_unlock(nd_output_mutex);
}

void nd_debug_printf(const char *format, ...)
{
    if (nd_debug) {
        va_list ap;
        va_start(ap, format);
        vfprintf(stderr, format, ap);
        va_end(ap);
    }
}

void ndpi_debug_printf(
    unsigned int i, void *p, ndpi_log_level_t l, const char *format, ...)
{
    if (nd_debug) {
        va_list ap;
        va_start(ap, format);
        vfprintf(stderr, format, ap);
        va_end(ap);
    }
}

void nd_print_address(const struct sockaddr_storage *addr)
{
    int rc;
    char _addr[NI_MAXHOST];

    switch (addr->ss_family) {
    case AF_INET:
        rc = getnameinfo((const struct sockaddr *)addr, sizeof(struct sockaddr_in),
            _addr, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
        break;
    case AF_INET6:
        rc = getnameinfo((const struct sockaddr *)addr, sizeof(struct sockaddr_in6),
            _addr, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
        break;
    default:
        nd_printf("(unsupported AF:%x)", addr->ss_family);
        return;
    }

    if (rc == 0)
        nd_printf(_addr);
    else
        nd_printf("???");
}

void nd_print_binary(uint32_t byte)
{
    uint32_t i;
    char b[sizeof(byte) * 8 + 1];

    b[0] = '\0';
    for (i = 0x80000000; i > 0; i >>= 1)
        strcat(b, ((byte & i) == i) ? "1" : "0");

    nd_printf(b);
}

int nd_sha1_file(const string &filename, uint8_t *digest)
{
    sha1 ctx;
    int fd = open(filename.c_str(), O_RDONLY);
    uint8_t buffer[ND_SHA1_BUFFER];
    ssize_t bytes;

    sha1_init(&ctx);

    if (fd < 0) {
        nd_printf("Unable to hash file: %s: %s\n",
            filename.c_str(), strerror(errno));
        return -1;
    }

    do {
        bytes = read(fd, buffer, ND_SHA1_BUFFER);

        if (bytes > 0)
            sha1_write(&ctx, (const char *)buffer, bytes);
        else if (bytes < 0) {
            nd_printf("Unable to hash file: %s: %s\n",
                filename.c_str(), strerror(errno));
            close(fd);
            return -1;
        }
    }
    while (bytes != 0);

    close(fd);
    memcpy(digest, sha1_result(&ctx), SHA1_DIGEST_LENGTH);

    return 0;
}

void nd_sha1_to_string(const uint8_t *digest_bin, string &digest_str)
{
    char _digest[SHA1_DIGEST_LENGTH * 2 + 1];
    char *p = _digest;

    for (int i = 0; i < SHA1_DIGEST_LENGTH; i++, p += 2)
        sprintf(p, "%02x", digest_bin[i]);

    digest_str.assign(_digest);
}

ndException::ndException(const string &where_arg, const string &what_arg) throw()
    : runtime_error(what_arg), where_arg(where_arg), what_arg(what_arg), message(NULL)
{
    ostringstream os;
    os << where_arg << ": " << what_arg;
    message = strdup(os.str().c_str());
}

ndException::~ndException() throw()
{
    if (message != NULL) free((void *)message);
}

const char *ndException::what() const throw()
{
    return message;
}

ndSystemException::ndSystemException(
    const string &where_arg, const string &what_arg, int why_arg) throw()
    : runtime_error(what_arg),
    where_arg(where_arg), what_arg(what_arg), why_arg(why_arg), message(NULL)
{
    ostringstream os;
    os << where_arg << ": " << what_arg << ": " << strerror(why_arg);
    message = strdup(os.str().c_str());
}

ndSystemException::~ndSystemException() throw()
{
    if (message != NULL) free((void *)message);
}

const char *ndSystemException::what() const throw()
{
    return message;
}

// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
