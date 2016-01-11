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

/*  I N C L U D E S  **********************************************************/
#include "config.h"

#ifdef HAVE_PFRING
#include <pfring.h>
#endif /* HAVE_PFRING */

#include "passivedns_common.h"

/*  D A T A  S T R U C T U R E S  *********************************************/

typedef struct _pdns_stat {
    uint32_t got_packets;    /* Number of packets received by program */
    uint32_t eth_recv;       /* Number of Ethernet packets received */
    uint32_t arp_recv;       /* Number of ARP packets received */
    uint32_t otherl_recv;    /* Number of other Link layer packets received */
    uint32_t vlan_recv;      /* Number of VLAN packets received */
    uint32_t ip4_recv;       /* Number of IPv4 packets received */
    uint32_t ip6_recv;       /* Number of IPv6 packets received */

    uint32_t ip4_dns_udp;    /* Number of IPv4 packets received */
    uint32_t ip4_dec_udp_ok; /* Number of IPv4 packets received */
    uint32_t ip4_dec_udp_er; /* Number of IPv4 packets received */
    uint32_t ip4_dns_tcp;    /* Number of IPv4 packets received */
    uint32_t ip4_dec_tcp_ok; /* Number of IPv4 packets received */
    uint32_t ip4_dec_tcp_er; /* Number of IPv4 packets received */
    uint32_t ip4_recv_tcp;   /* Number of IPv4 packets received */

    uint32_t ip6_dns_udp;    /* Number of IPv4 packets received */
    uint32_t ip6_dec_udp_ok; /* Number of IPv4 packets received */
    uint32_t ip6_dec_udp_er; /* Number of IPv4 packets received */
    uint32_t ip6_dns_tcp;    /* Number of IPv4 packets received */
    uint32_t ip6_dec_tcp_ok; /* Number of IPv4 packets received */
    uint32_t ip6_dec_tcp_er; /* Number of IPv4 packets received */
    uint32_t ip6_recv_tcp;   /* Number of IPv4 packets received */

    uint32_t ip4ip_recv;     /* Number of IP4/6 packets in IPv4 packets */
    uint32_t ip6ip_recv;     /* Number of IP4/6 packets in IPv6 packets */
    uint32_t gre_recv;       /* Number of GRE packets received */
    uint32_t tcp_recv;       /* Number of TCP packets received */
    uint32_t udp_recv;       /* Number of UDP packets received */
    uint32_t icmp_recv;      /* Number of ICMP packets received */
    uint32_t othert_recv;    /* Number of other transport layer packets received */
    uint32_t dns_records;    /* Total number of DNS records detected */
    uint32_t dns_assets;     /* Total number of DNS assets detected */
    uint32_t tcp_os_assets;  /* Total number of TCP os assets detected */
    uint32_t udp_os_assets;  /* Total number of UDP os assets detected */
    uint32_t icmp_os_assets; /* Total number of ICMP os assets detected */
    uint32_t dhcp_os_assets; /* Total number of DHCP os assets detected */
    uint32_t tcp_services;   /* Total number of TCP services detected */
    uint32_t tcp_clients;    /* Total number of TCP clients detected */
    uint32_t udp_services;   /* Total number of UDP services detected */
    uint32_t udp_clients;    /* Total number of TCP clients detected */
} pdns_stat;

#define CONFIG_VERBOSE 0x01
#define CONFIG_UPDATES 0x02
#define CONFIG_SYSLOG  0x04
#define CONFIG_QUIET   0x08
#define CONFIG_CONNECT 0x10
#define CONFIG_CXWRITE 0x20

#define INTERRUPT_END      0x01
#define INTERRUPT_SESSION  0x02
#define INTERRUPT_DNS      0x04

typedef struct _output_plugin {
    char    *name;
    void    *handle;
    int     (*start)();
    void    (*stop)();
    _output (*output);
    void    (*getopt)(int *, char **[]);
    void    (*usage)();
} output_plugin;

typedef struct _globalconfig {
    pcap_t              *handle;           /* Pointer to libpcap handle */
#ifdef HAVE_PFRING
    pfring              *pfhandle;         /* Pointer to libpfring handle */
    uint8_t             use_pfring;        /* Use PF_RING or not */
    u_int               cluster_id;        /* PF_RING cluster ID */
#endif /* HAVE_PFRING */
    struct pcap_stat    ps;                /* Libpcap stats */
    int                 linktype;          /* Libpcap linktype */
    pdns_stat           p_s;               /* PDNS stats */
    struct bpf_program  cfilter;
    bpf_u_int32         net_mask;
    uint8_t             intr_flag;
    uint8_t             inpacket;

    time_t              dnslastchk;        /* Timestamp for last DNS cache expiration check */
    struct timeval      tstamp;            /* Current timestamp from packet-header */
    uint8_t             cflags;            /* Config flags */
    uint8_t             verbose;           /* Verbose or not */
    uint8_t             print_updates;     /* Prints updates */
    uint8_t             output_log;        /* Log to log file */
    uint8_t             output_log_nxd;    /* Log NXDOMAIN to log file */
    uint8_t             output_syslog;     /* Log to syslog */
    uint8_t             output_syslog_nxd; /* Log NXDOMAIN to syslog */
    output_plugin       *output_plugin;     /* Output Plugin */
#ifdef HAVE_JSON
    uint8_t             use_json;          /* Use JSON as output in log */
    uint8_t             use_json_nxd;      /* Use JSON as output in NXDOMAIN log */
#endif /* HAVE_JSON */
    uint8_t             setfilter;
    uint8_t             drop_privs_flag;   /* Flag marking to drop privs */
    uint8_t             chroot_flag;       /* Flag for going chroot */
    uint8_t             daemon_flag;       /* Flag for going daemon */
    uint8_t             logfile_all;       /* Log everything in the same log file */
    uint32_t            fieldsf;           /* flags for fields to print */
    uint64_t            dnsf;              /* Flags for DNS RR Type checks to do */
    uint32_t            dnsfe;             /* Flags for DNS Server Error Types to check */
    uint32_t            payload;           /* Dump how much of the payload ?  */
    uint32_t            curcxt;
    uint32_t            llcxt;
    uint64_t            mem_limit_max;     /* Try soft limit memory use */
    uint64_t            mem_limit_size;    /* Current memory size */
    uint32_t            dns_records;       /* Total number of DNS records in memory */
    uint32_t            dns_assets;        /* Total number of DNS assets in memory */
    uint64_t            cxtrackerid;       /* cxtracker ID counter */
    char                errbuf[PCAP_ERRBUF_SIZE];
    char                *bpff;
    char                *user_filter;
    char                *net_ip_string;
    char                *log_delimiter;    /* Delimiter between fields in log */
    char                *logfile;          /* Filename of /var/log/passivedns.log */
    char                *logfile_nxd;      /* Filename for NXDOMAIN logging /var/log/passivedns-nxd.log */
    char                *pcap_file;        /* Filename to PCAP too read */
    FILE                *logfile_fd;       /* File descriptor for log file */
    FILE                *logfile_nxd_fd;   /* File descriptor for NXDOMAIN log file */
    char                *dev;              /* Device name to use for sniffing */
    char                *dpath;            /* ... ??? seriously ???... */
    char                *chroot_dir;       /* Directory to chroot to */
    char                *group_name;       /* Group to drop privileges too */
    char                *user_name;        /* User to drop privileges too */
    char                *pidfile;          /* Pidfile */
    char                *configpath;       /* Path to config directory */
    uint32_t            dnsprinttime;      /* Minimum time between printing duplicate DNS info */
    uint32_t            dnscachetimeout;   /* Time before a DNS record/asset times out if not updated */
} globalconfig;

#define ISSET_CONFIG_VERBOSE(config)    ((config).cflags & CONFIG_VERBOSE)
#define ISSET_CONFIG_UPDATES(config)    ((config).cflags & CONFIG_UPDATES)
#define ISSET_CONFIG_SYSLOG(config)     ((config).cflags & CONFIG_SYSLOG)
#define ISSET_CONFIG_QUIET(config)      ((config).cflags & CONFIG_QUIET)

#define ISSET_INTERRUPT_END(config)     ((config).intr_flag & INTERRUPT_END)
#define ISSET_INTERRUPT_SESSION(config) ((config).intr_flag & INTERRUPT_SESSION)
#define ISSET_INTERRUPT_DNS(config)     ((config).intr_flag & INTERRUPT_DNS)

#define plog(fmt, ...) do{ fprintf(stdout, (fmt), ##__VA_ARGS__); }while(0)
#define olog(fmt, ...) do{ if(!(ISSET_CONFIG_QUIET(config))) fprintf(stdout, (fmt), ##__VA_ARGS__); }while(0)
//#define DEBUG 1
#ifdef DEBUG
#define dlog(fmt, ...) do { fprintf(stderr, ("[%s:%d(%s)] " fmt), __FILE__, __LINE__, __PRETTY_FUNCTION__, ##__VA_ARGS__);} while(0)
#define vlog(v, fmt, ...) do{ if(DEBUG == v) fprintf(stderr, ("[%s:%d(%s)] " fmt), __FILE__, __LINE__, __PRETTY_FUNCTION__, ##__VA_ARGS__); }while(0)
#define elog(fmt, ...) fprintf(stderr, ("[%s:%d(%s)] " fmt), __FILE__, __LINE__, __PRETTY_FUNCTION__, ##__VA_ARGS__);
#else
#define elog(fmt, ...) fprintf(stderr, (fmt), ##__VA_ARGS__);
#define dlog(fmt, ...) do { ; } while(0)
#define vlog(fmt, ...) do { ; } while(0)
#endif

int cxt_update_client(connection *cxt, packetinfo *pi);
int cxt_update_unknown(connection *cxt, packetinfo *pi);
int cxt_update_server(connection *cxt, packetinfo *pi);

