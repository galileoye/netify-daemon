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

#ifndef _ND_CONNTRACK_H
#define _ND_CONNTRACK_H

class ndConntrackThreadException : public runtime_error
{
public:
    explicit ndConntrackThreadException(const string &what_arg)
        : runtime_error(what_arg) { }
};

class ndConntrackSystemException : public ndSystemException
{
public:
    explicit ndConntrackSystemException(
        const string &where_arg, const string &what_arg, int why_arg) throw()
        : ndSystemException(where_arg, what_arg, why_arg) { }
};

class ndConntrackFlowException : public runtime_error
{
public:
    explicit ndConntrackFlowException(const string &what_arg)
        : runtime_error(what_arg) { }
};

enum ndConntrackFlowDirection
{
    ndCT_DIR_SRC = 0,
    ndCT_DIR_DST = 1
};

class ndConntrackFlow
{
public:
    ndConntrackFlow(struct nf_conntrack *ct);
    virtual ~ndConntrackFlow();

    void Update(struct nf_conntrack *ct);

protected:
    friend class ndConntrackThread;

    void CopyAddress(sa_family_t af, struct sockaddr_storage *dst, const void *src);
    void Hash(void);

    string digest;
    sa_family_t l3_proto;
    uint8_t l4_proto;
    uint16_t orig_port[2];
    uint16_t repl_port[2];
    struct sockaddr_storage *orig_addr[2];
    struct sockaddr_storage *repl_addr[2];
};

typedef unordered_map<uint32_t, string> nd_ct_id_map;
typedef unordered_map<string, ndConntrackFlow *> nd_ct_flow_map;

class ndConntrackThread : public ndThread
{
public:
    ndConntrackThread();
    virtual ~ndConntrackThread();

    virtual void Terminate(void) { terminate = true; }

    virtual void *Entry(void);

    void ProcessConntrackEvent(
        enum nf_conntrack_msg_type type, struct nf_conntrack *ct);

    void ClassifyFlow(ndFlow *flow);

protected:
    void DumpConntrackTable(void);

    void PrintFlow(ndFlow *flow, string &text);
    void PrintFlow(ndConntrackFlow *flow, string &text,
        bool reorder = false, bool withreply = false);

    int ctfd;
    nfct_handle *cth;
    bool terminate;
    int cb_registered;
    nd_ct_id_map ct_id_map;
    nd_ct_flow_map ct_flow_map;
};

#endif // _ND_CONNTRACK_H
// vi: expandtab shiftwidth=4 softtabstop=4 tabstop=4
