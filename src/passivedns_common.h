/*
** This file is a part of PassiveDNS.
**
** Copyright (C) 2010-2013, Edward Fjellskål <edwardfjellskaal@gmail.com>
**
** This program is free software; you can redistribute it and/or modify
** it under the terms of the GNU General Public License as published by
** the Free Software Foundation; either version 2 of the License, or
** (at your option) any later version.
**
** This program is distributed in the hope that it will be useful,
** but WITHOUT ANY WARRANTY; without even the implied warranty of
** MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
** GNU General Public License for more details.
**
** You should have received a copy of the GNU General Public License
** along with this program; if not, write to the Free Software
** Foundation, Inc., 59 Temple Place - Suite 330, Boston, MA 02111-1307, USA.
**
*/

/*  D E F I N E S  ************************************************************/
#define TIMEOUT                       60
#define BUCKET_SIZE                   65537
#define SNAPLENGTH                    1600
#define PKT_MAXPAY                    255
#define MAX_BYTE_CHECK                500000
#define MAX_PKT_CHECK                 10
#define TCP_TIMEOUT                   300       /* When idle IP connections should be timed out */
#define UDP_TIMEOUT                   60
#define ICMP_TIMEOUT                  60
#define OTHER_TIMEOUT                 300

#define ETHERNET_TYPE_IP              0x0800
#define ETHERNET_TYPE_IPV6            0x86dd

#define ETHERNET_TYPE_8021Q           0x8100
#define ETHERNET_TYPE_802Q1MT         0x9100
#define ETHERNET_TYPE_802Q1MT2        0x9200
#define ETHERNET_TYPE_802Q1MT3        0x9300
#define ETHERNET_TYPE_8021AD          0x88a8

#define IP_PROTO_ICMP                 1
#define IP_PROTO_TCP                  6
#define IP_PROTO_UDP                  17
#define IP_PROTO_IP6                  41
#define IP6_PROTO_ICMP                58

#define SLL_HDR_LEN                   16
#define IP4_HEADER_LEN                20
#define IP6_HEADER_LEN                40
#define TCP_HEADER_LEN                20
#define UDP_HEADER_LEN                8
#define MAC_ADDR_LEN                  6
#define ETHERNET_HEADER_LEN           14
#define ETHERNET_8021Q_HEADER_LEN     18
#define ETHERNET_802Q1MT_HEADER_LEN   22

#define IP_PROTO_TCP                  6
#define IP_PROTO_UDP                  17
#define IP_PROTO_IP6                  41
#define IP_PROTO_IP4                  94

#define TF_FIN                        0x01
#define TF_SYN                        0x02
#define TF_RST                        0x04
#define TF_PUSH                       0x08
#define TF_ACK                        0x10
#define TF_URG                        0x20
#define TF_ECE                        0x40
#define TF_CWR                        0x80

#define SUCCESS                       0
#define ERROR                         1
#define STDBUF                        1024

#define BPFF "port 53"                          /* Default BPF filter */

#if defined(__FreeBSD__) || defined(__APPLE__)
#define s6_addr32   __u6_addr.__u6_addr32
#endif /* __FreeBSD__ or __APPLE__ */

/*  D A T A  S T R U C T U R E S  *********************************************/

/*
 * Ethernet header
 */

typedef struct _ether_header {
    u_char  ether_dst[6];              /* Destination MAC */
    u_char  ether_src[6];              /* Source MAC */

    union
    {
        struct etht
        {
            u_short ether_type;        /* Ethernet type (normal) */
        } etht;

        struct qt
        {
            u_short eth_t_8021;        /* Ethernet type/802.1Q tag */
            u_short eth_t_8_vid;
            u_short eth_t_8_type;
        } qt;

        struct qot
        {
            u_short eth_t_80212;       /* Ethernet type/802.1QinQ */
            u_short eth_t_82_mvid;
            u_short eth_t_82_8021;
            u_short eth_t_82_vid;
            u_short eth_t_82_type;
        } qot;
    } vlantag;

    #define eth_ip_type    vlantag.etht.ether_type

    #define eth_8_type     vlantag.qt.eth_t_8021
    #define eth_8_vid      vlantag.qt.eth_t_8_vid
    #define eth_8_ip_type  vlantag.qt.eth_t_8_type

    #define eth_82_type    vlantag.qot.eth_t_80212
    #define eth_82_mvid    vlantag.qot.eth_t_82_mvid
    #define eth_82_8021    vlantag.qot.eth_t_82_8021
    #define eth_82_vid     vlantag.qot.eth_t_82_vid
    #define eth_82_ip_type vlantag.qot.eth_t_82_type

} ether_header;

typedef struct _arphdr {
    uint16_t ar_hrd;            /* Format of hardware address */
    uint16_t ar_pro;            /* Format of protocol address */
    uint8_t ar_hln;             /* Length of hardware address */
    uint8_t ar_pln;             /* Length of protocol address */
    uint16_t ar_op;             /* ARP opcode (command) */
} arphdr;

typedef struct _ether_arp {
    arphdr ea_hdr;                   /* Fixed-size header */
    uint8_t arp_sha[MAC_ADDR_LEN];   /* Sender hardware address */
    uint8_t arp_spa[4];              /* Sender protocol address */
    uint8_t arp_tha[MAC_ADDR_LEN];   /* Target hardware address */
    uint8_t arp_tpa[4];              /* Target protocol address */
} ether_arp;

/*
 * IPv4 header
 */

typedef struct _ip4_header {
    uint8_t  ip_vhl;                 /* Version << 4 | header length >> 2 */
    uint8_t  ip_tos;                 /* Type of service */
    uint16_t ip_len;                 /* Total length */
    uint16_t ip_id;                  /* Identification */
    uint16_t ip_off;                 /* Fragment offset field */
    uint8_t  ip_ttl;                 /* Time to live */
    uint8_t  ip_p;                   /* Protocol */
    uint16_t ip_csum;                /* Checksum */
    uint32_t ip_src;                 /* Source address */
    uint32_t ip_dst;                 /* Destination address */
} ip4_header;

#define IP_RF 0x8000                 /* Reserved fragment flag */
#define IP_DF 0x4000                 /* Don't fragment flag */
#define IP_MF 0x2000                 /* More fragments flag */
#define IP_OFFMASK 0x1fff            /* Mask for fragmenting bits */
#define IP_HL(ip4_header) (((ip4_header)->ip_vhl) & 0x0f)
#define IP_V(ip4_header)  (((ip4_header)->ip_vhl) >> 4)

/*
 * IPv6 header
 */

typedef struct _ip6_header {
    uint32_t vcl;                    /* Version, class, and label */
    uint16_t len;                    /* Length of the payload */
    uint8_t  next;                   /* Next header
                                      * Uses the same flags as
                                      * the IPv4 protocol field */
    uint8_t  hop_lmt;                /* Hop limit */
    struct in6_addr ip_src;          /* Source address */
    struct in6_addr ip_dst;          /* Destination address */
} ip6_header;

/*
 * TCP header
 */

typedef struct _tcp_header {
    uint16_t  src_port;              /* Source port */
    uint16_t  dst_port;              /* Destination port */
    uint32_t  t_seq;                 /* Sequence number */
    uint32_t  t_ack;                 /* Acknowledgement number */
    uint8_t   t_offx2;               /* Data offset, rsvd */
    uint8_t   t_flags;               /* TCP flags */
    uint16_t  t_win;                 /* Window */
    uint16_t  t_csum;                /* Checksum */
    uint16_t  t_urgp;                /* Urgent pointer */
} tcp_header;

#define TCP_OFFSET(tcp_header)           (((tcp_header)->t_offx2 & 0xf0) >> 4)
#define TCP_X2(tcp_header)               ((tcp_header)->t_offx2 & 0x0f)
#define TCP_ISFLAGSET(tcp_header, flags) (((tcp_header)->t_flags & (flags)) == (flags))

/*
 * UDP header
 */

typedef struct _udp_header {
    uint16_t src_port;               /* Source port */
    uint16_t dst_port;               /* Destination port */
    uint16_t len;                    /* Length of the payload */
    uint16_t csum;                   /* Checksum */
} udp_header;

/*
 * Structure for connections
 */

typedef struct _connection {
    struct   _connection *prev;
    struct   _connection *next;
    time_t   start_time;          /* Connection start time */
    time_t   last_pkt_time;       /* Last seen packet time */
    uint64_t cxid;                /* Connection ID */
    uint8_t  reversed;            /* 1 if the connection is reversed */
    uint32_t af;                  /* IP version (4/6) AF_INET */
    uint8_t  proto;               /* IP protocol type */
    struct   in6_addr s_ip;       /* Source address */
    struct   in6_addr d_ip;       /* Destination address */
    uint16_t s_port;              /* Source port */
    uint16_t d_port;              /* Destination port */
    uint64_t s_total_pkts;        /* Total source packets */
    uint64_t s_total_bytes;       /* Total source bytes */
    uint64_t d_total_pkts;        /* Total destination packets */
    uint64_t d_total_bytes;       /* Total destination bytes */
    uint8_t  s_tcpFlags;          /* TCP flags sent by source */
    uint8_t  d_tcpFlags;          /* TCP flags sent by destination */
    uint8_t  check;               /* Flags specifying checking */
    uint16_t plid;                /* Protocol layer ID (DNS TID) */
} connection;
#define CXT_DONT_CHECK_SERVER     0x01  /* Don't check server packets */
#define CXT_DONT_CHECK_CLIENT     0x02  /* Don't check client packets */
#define CXT_SERVICE_DONT_CHECK    0x04  /* Don't check payload from server */
#define CXT_CLIENT_DONT_CHECK     0x08  /* Don't check payload from client */
#define CXT_SERVICE_UNKNOWN_SET   0x10  /* If service is set as unknown */
#define CXT_CLIENT_UNKNOWN_SET    0x20  /* If client is set as unknown */

#define ISSET_CXT_DONT_CHECK_CLIENT(pi)  (pi->cxt->check & CXT_DONT_CHECK_CLIENT)
#define ISSET_CXT_DONT_CHECK_SERVER(pi)  (pi->cxt->check & CXT_DONT_CHECK_SERVER)
#define ISSET_DONT_CHECK_SERVICE(pi)     (pi->cxt->check & CXT_SERVICE_DONT_CHECK)
#define ISSET_DONT_CHECK_CLIENT(pi)      (pi->cxt->check & CXT_CLIENT_DONT_CHECK)
#define ISSET_SERVICE_UNKNOWN(pi)        (pi->cxt->check & CXT_SERVICE_UNKNOWN_SET)
#define ISSET_CLIENT_UNKNOWN(pi)         (pi->cxt->check & CXT_CLIENT_UNKNOWN_SET)

#ifdef OSX
// sidds darwin ports
#define IP4ADDR(ip) (ip)->__u6_addr.__u6_addr32[0]

#define CMP_ADDR6(a1,a2) \
    (((a1)->__u6_addr.__u6_addr32[3] == (a2)->__u6_addr.__u6_addr32[3] && \
      (a1)->__u6_addr.__u6_addr32[2] == (a2)->__u6_addr.__u6_addr32[2] && \
      (a1)->__u6_addr.__u6_addr32[1] == (a2)->__u6_addr.__u6_addr32[1] && \
      (a1)->__u6_addr.__u6_addr32[0] == (a2)->__u6_addr.__u6_addr32[0]))

// The reason why we can't get rid of pi->s6_addr32
#define CMP_ADDR4(a1,a2) \
    (((a1)->__u6_addr.__u6_addr32[0] ==  (a2)))
#define CMP_ADDRA(a1,a2) \
    (((a1)->__u6_addr.__u6_addr32[0] == (a2)->__u6_addr.__u6_addr32[0]))

#define CMP_PORT(p1,p2) \
    ((p1 == p2))
#else
#define IP6ADDR0(ip) ((ip)->s6_addr32[0])
#define IP6ADDR1(ip) ((ip)->s6_addr32[1])
#define IP6ADDR2(ip) ((ip)->s6_addr32[2])
#define IP6ADDR3(ip) ((ip)->s6_addr32[3])
#define IP6ADDR(ip) \
    IP6ADDR0(ip), IP6ADDR1(ip), IP6ADDR2(ip), IP6ADDR3(ip)

#define IP4ADDR(ip) ((ip)->s6_addr32[0])

#define CMP_ADDR6(a1,a2) \
    (((a1)->s6_addr32[3] == (a2)->s6_addr32[3] && \
      (a1)->s6_addr32[2] == (a2)->s6_addr32[2] && \
      (a1)->s6_addr32[1] == (a2)->s6_addr32[1] && \
      (a1)->s6_addr32[0] == (a2)->s6_addr32[0]))

// The reason why we can't get rid of pi->s6_addr32
// apples and apples
#define CMP_ADDR4A(a1,a2) \
    ((a1)->s6_addr32[0] == (a2)->s6_addr32[0])
// apples and oranges
#define CMP_ADDR4(apple,orange) \
    (((apple)->s6_addr32[0] ==  (orange)))
#define CMP_PORT(p1,p2) \
    ((p1 == p2))
#endif /* OSX */

/* Since two or more connections can have the same hash key, we need to
 * compare the connections with the current hash key. */
#define CMP_CXT4(cxt1, src, sp, dst, dp) \
    (( \
       CMP_PORT((cxt1)->s_port, (sp)) && \
       CMP_PORT((cxt1)->d_port, (dp)) && \
       CMP_ADDR4(&((cxt1)->s_ip), (src)) && \
       CMP_ADDR4(&((cxt1)->d_ip), (dst))    \
    ))

#define CMP_CXT6(cxt1, src, sp, dst, dp) \
    ((CMP_ADDR6(&(cxt1)->s_ip, (src)) && \
       CMP_ADDR6(&(cxt1)->d_ip, (dst)) && \
       CMP_PORT((cxt1)->s_port, (sp)) && CMP_PORT((cxt1)->d_port, (dp))))

/* clear the address structure by setting all fields to 0 */
#ifdef OSX
#define CLEAR_ADDR(a) { \
    (a)->__u6_addr.__u6_addr32[0] = 0; \
    (a)->__u6_addr.__u6_addr32[1] = 0; \
    (a)->__u6_addr.__u6_addr32[2] = 0; \
    (a)->__u6_addr.__u6_addr32[3] = 0; \
}
#else
#define CLEAR_ADDR(a) { \
    (a)->s6_addr32[0] = 0; \
    (a)->s6_addr32[1] = 0; \
    (a)->s6_addr32[2] = 0; \
    (a)->s6_addr32[3] = 0; \
}
#endif

#define CXT_HASH4(src,dst,sp,dp,pr) \
   ((src + dst + sp + dp + pr) % BUCKET_SIZE)

#ifndef OSX
#define CXT_HASH6(src,dst,sp,dp,pr) \
 (( \
  (src)->s6_addr32[0] + (src)->s6_addr32[1] + \
  (src)->s6_addr32[2] + (src)->s6_addr32[3] + \
  (dst)->s6_addr32[0] + (dst)->s6_addr32[1] + \
  (dst)->s6_addr32[2] + (dst)->s6_addr32[3] + \
  sp + dp + pr ) % BUCKET_SIZE)
#else
#define CXT_HASH6(src,dest,sp,dp,pr) \
 (( \
  (src)->__u6_addr.__u6_addr32[0] + (src)->__u6_addr.__u6_addr32[1] + \
  (src)->__u6_addr.__u6_addr32[2] + (src)->__u6_addr.__u6_addr32[3] + \
  (dst)->__u6_addr.__u6_addr32[0] + (dst)->__u6_addr.__u6_addr32[1] + \
  (dst)->__u6_addr.__u6_addr32[2] + (dst)->__u6_addr.__u6_addr32[3] + \
  sp + dp + pr ) % BUCKET_SIZE)
#endif

typedef struct _packetinfo {
    /* Macro out the need for some of these
     * eth_type(pi) is same as pi->eth_type, no?
     * marked candidates for deletion */
    const struct pcap_pkthdr *pheader; /* Libpcap packet header struct pointer */
    const uint8_t   *packet;           /* Unsigned char pointer to raw packet */
    /* Compute (all) these from packet */
    uint32_t        eth_hlen;         /* Ethernet header length */
    uint16_t        mvlan;            /* Metro vlan tag */
    uint16_t        vlan;             /* VLAN tag */
    uint16_t        eth_type;         /* Ethernet type (IPv4/IPv6/etc) */
    uint32_t        af;               /* IP version (4/6) AF_INET */
    ether_header    *eth_hdr;         /* Ethernet header struct pointer */
    ether_arp       *arph;            /* ARP header struct pointer */
    ip4_header      *ip4;             /* IPv4 header struct pointer */
    ip6_header      *ip6;             /* IPv6 header struct pointer */
    uint16_t        packet_bytes;     /* Length of IP payload in packet */
    uint16_t        s_port;           /* Source port */
    uint16_t        d_port;           /* Destination port */
    uint8_t         proto;            /* IP protocol type */
    uint8_t         sc;               /* SC_SERVER, SC_CLIENT or SC_UNKNOWN */
    tcp_header      *tcph;            /* TCP header struct pointer */
    udp_header      *udph;            /* UDP header struct pointer */
    uint16_t        gre_hlen;         /* Length of dynamic GRE header length */
    const uint8_t   *end_ptr;         /* Paranoid end pointer of packet */
    const uint8_t   *payload;         /* Char pointer to transport payload */
    uint32_t        plen;             /* Transport payload length */
    uint32_t        our;              /* Is the asset in our defined network */
    uint8_t         up;               /* Set if the asset has been updated */
    connection      *cxt;             /* Pointer to the cxt for this packet */
} packetinfo;

/*
 * Packetinfo accessor macros
 */

#define PI_TOS(pi) ( (pi)->ip4->ip_tos )
#define PI_ECN(pi) ( (pi)->tcph->t_flags & (TF_ECE|TF_CWR) )

#define PI_IP4(pi) ((pi)->ip4)
#define PI_IP4SRC(pi) ( PI_IP4(pi)->ip_src )
#define PI_IP4DST(pi) ( PI_IP4(pi)->ip_dst )

#define PI_IP6(pi) ((pi)->ip6)
#define PI_IP6SRC(pi)  (PI_IP6(pi)->ip_src)
#define PI_IP6DST(pi)  (PI_IP6(pi)->ip_dst)

#define PI_TCP_SP(pi) ( ntohs((pi)->tcph->src_port))
#define PI_TCP_DP(pi) ( ntohs((pi)->tcph->dst_port))

#define SC_CLIENT                 0x01  /* Pi for this session is client */
#define SC_SERVER                 0x02  /* Pi for this session is server */
#define SC_UNKNOWN                0x03  /* Pi for this session is not yet known */


#include "dns.h"

typedef void _output(pdns_record *l,
                     pdns_asset *p,
                     ldns_rr *rr,
                     ldns_rdf *lname, uint16_t rcode);
