
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>
#include <arpa/inet.h>
#include <arpa/nameser.h>
#include <netinet/in.h>
#include <resolv.h>

#include <jansson.h>

#include <passivedns_common.h>


typedef struct _outputconfig {
    uint8_t             output_log;        /* Log to log file */
    uint8_t             output_log_nxd;    /* Log NXDOMAIN to log file */

    char                *logfile;          /* Filename of /var/log/passivedns.log */
    char                *logfile_nxd;      /* Filename for NXDOMAIN logging /var/log/passivedns-nxd.log */
    uint8_t             logfile_all;       /* Log everything in the same log file */
    uint32_t            fieldsf;           /* flags for fields to print */

    FILE                *logfile_fd;       /* File descriptor for log file */
    FILE                *logfile_nxd_fd;   /* File descriptor for NXDOMAIN log file */
} outputconfig_t;

outputconfig_t outputconfig;


void
json_usage() {

}

void
json_getopt(int *argc, char** argv[]) {
    int ch = 0;

    memset(&outputconfig, 0, sizeof(outputconfig_t));
    outputconfig.logfile = "/var/log/passivedns.log";
    outputconfig.logfile_nxd = "/var/log/passivedns.log";
    outputconfig.fieldsf = parse_field_flags("");

#define ARGS "l:L:f:"

    while ((ch = getopt(*argc, *argv, ARGS)) != -1) {
        switch (ch) {
        case 'l':
            outputconfig.output_log_nxd = 1;
            outputconfig.logfile_nxd = optarg;
            break;
        case 'L':
            outputconfig.output_log = 1;
            outputconfig.logfile = optarg;
            break;
        case 'f':
            outputconfig.fieldsf = parse_field_flags(optarg);
            break;
        }
    }
    
    /* Open log file */
    if (outputconfig.output_log) {
        if (outputconfig.logfile[0] == '-' && outputconfig.logfile[1] == '\0') {
            outputconfig.logfile_fd = stdout;
        }
        else {
            outputconfig.logfile_fd = fopen(outputconfig.logfile, "a");
            if (outputconfig.logfile_fd == NULL) {
                exit(1);
            }
        }
    }

    /* Open NXDOMAIN log file */
    if (outputconfig.output_log_nxd) {
        if (outputconfig.output_log && strcmp(outputconfig.logfile, outputconfig.logfile_nxd) == 0) {
            outputconfig.logfile_all = 1;
        }
        else if (outputconfig.logfile_nxd[0] == '-' && outputconfig.logfile_nxd[1] == '\0') {
            outputconfig.logfile_nxd_fd = stdout;
        }
        else {
            outputconfig.logfile_nxd_fd = fopen(outputconfig.logfile_nxd, "a");
            if (outputconfig.logfile_nxd_fd == NULL) {
                exit(1);
            }
        }
    }
}

int
json_start() {

    return 0;
}

void
json_stop() {

}

void
json_output(pdns_record *l, pdns_asset *p, ldns_rr *rr,
            ldns_rdf *lname, uint16_t rcode) {

    FILE *fd = NULL;
    static char ip_addr_s[INET6_ADDRSTRLEN];
    static char ip_addr_c[INET6_ADDRSTRLEN];
    char *rr_class;
    char *rr_type;
    char *rr_rcode;
    char buffer[1000] = "";
    char *output = buffer;
    int offset = 0;
    uint8_t is_err_record = 0;

    json_t *jdata;
    json_t *json_timestamp_s;
    json_t *json_timestamp_ms;
    json_t *json_client;
    json_t *json_server;
    json_t *json_class;
    json_t *json_query;
    json_t *json_type;
    json_t *json_answer;
    json_t *json_ttl;
    json_t *json_count;
    size_t data_flags = 0;

    /* Print in the same order as inserted */
    data_flags |= JSON_PRESERVE_ORDER;

    /* No whitespace between fields */
    data_flags |= JSON_COMPACT;

    /* If pdns_asset is not defined, then this is a NXD record */
    if (p == NULL) {
        is_err_record = 1;
    }

    /* Use the correct file descriptor */
    if (is_err_record && outputconfig.output_log_nxd) {
        if (outputconfig.logfile_all) {
            fd = outputconfig.logfile_fd;
        }
        else {
            fd = outputconfig.logfile_nxd_fd;
        }
        if (fd == NULL) return;
    }
    else if (!is_err_record && outputconfig.output_log) {
        fd = outputconfig.logfile_fd;
        if (fd == NULL) return;
    }

    if (is_err_record) {
        u_ntop(l->sip, l->af, ip_addr_s);
        u_ntop(l->cip, l->af, ip_addr_c);
    }
    else {
        u_ntop(p->sip, p->af, ip_addr_s);
        u_ntop(p->cip, p->af, ip_addr_c);
    }

    rr_class = malloc(10);
    rr_type  = malloc(12);
    rr_rcode = malloc(20);

    switch (ldns_rr_get_class(rr)) {
        case LDNS_RR_CLASS_IN:
            snprintf(rr_class, 10, "IN");
            break;
        case LDNS_RR_CLASS_CH:
            snprintf(rr_class, 10, "CH");
            break;
        case LDNS_RR_CLASS_HS:
            snprintf(rr_class, 10, "HS");
            break;
        case LDNS_RR_CLASS_NONE:
            snprintf(rr_class, 10, "NONE");
            break;
        case LDNS_RR_CLASS_ANY:
            snprintf(rr_class, 10, "ANY");
            break;
        default:
            snprintf(rr_class, 10, "%d", ldns_rr_get_class(rr));
            break;
    }

    switch (ldns_rr_get_type(rr)) {
        case LDNS_RR_TYPE_HINFO:
            snprintf(rr_type, 10, "HINFO");
            break;
        case LDNS_RR_TYPE_SSHFP:
            snprintf(rr_type, 10, "SSHFP");
            break;
        case LDNS_RR_TYPE_GPOS:
            snprintf(rr_type, 10, "GPOS");
            break;
        case LDNS_RR_TYPE_LOC:
            snprintf(rr_type, 10, "LOC");
            break;
        case LDNS_RR_TYPE_DNSKEY:
            snprintf(rr_type, 10, "DNSKEY");
            break;
#ifdef LDNS_RR_TYPE_NSEC3PARAM
        case LDNS_RR_TYPE_NSEC3PARAM:
            snprintf(rr_type, 11, "NSEC3PARAM");
            break;
#endif /* LDNS_RR_TYPE_NSEC3PARAM */
        case LDNS_RR_TYPE_NSEC3:
            snprintf(rr_type, 10, "NSEC3");
            break;
        case LDNS_RR_TYPE_NSEC:
            snprintf(rr_type, 10, "NSEC");
            break;
        case LDNS_RR_TYPE_RRSIG:
            snprintf(rr_type, 10, "RRSIG");
            break;
        case LDNS_RR_TYPE_DS:
            snprintf(rr_type, 10, "DS");
            break;
        case LDNS_RR_TYPE_PTR:
            snprintf(rr_type, 10, "PTR");
            break;
        case LDNS_RR_TYPE_A:
            snprintf(rr_type, 10, "A");
            break;
        case LDNS_RR_TYPE_AAAA:
            snprintf(rr_type, 10, "AAAA");
            break;
        case LDNS_RR_TYPE_CNAME:
            snprintf(rr_type, 10, "CNAME");
            break;
        case LDNS_RR_TYPE_DNAME:
            snprintf(rr_type, 10, "DNAME");
            break;
        case LDNS_RR_TYPE_NAPTR:
            snprintf(rr_type, 10, "NAPTR");
            break;
        case LDNS_RR_TYPE_RP:
            snprintf(rr_type, 10, "RP");
            break;
        case LDNS_RR_TYPE_SRV:
            snprintf(rr_type, 10, "SRV");
            break;
        case LDNS_RR_TYPE_TXT:
            snprintf(rr_type, 10, "TXT");
            break;
        case LDNS_RR_TYPE_SPF:
            snprintf(rr_type, 10, "SPF");
            break;
        case LDNS_RR_TYPE_SOA:
            snprintf(rr_type, 10, "SOA");
            break;
        case LDNS_RR_TYPE_NS:
            snprintf(rr_type, 10, "NS");
            break;
        case LDNS_RR_TYPE_MX:
            snprintf(rr_type, 10, "MX");
            break;
        default:
            if (is_err_record) {
                snprintf(rr_type, 10, "%d", ldns_rdf_get_type(lname));
            }
            else {
                snprintf(rr_type, 10, "%d", p->rr->_rr_type);
            }
            break;
    }

    if (is_err_record) {
        switch (rcode) {
            case 1:
                snprintf(rr_rcode, 20, "FORMERR");
                break;
            case 2:
                snprintf(rr_rcode, 20, "SERVFAIL");
                break;
            case 3:
                snprintf(rr_rcode, 20, "NXDOMAIN");
                break;
            case 4:
                snprintf(rr_rcode, 20, "NOTIMPL");
                break;
            case 5:
                snprintf(rr_rcode, 20, "REFUSED");
                break;
            case 6:
                snprintf(rr_rcode, 20, "YXDOMAIN");
                break;
            case 7:
                snprintf(rr_rcode, 20, "YXRRSET");
                break;
            case 8:
                snprintf(rr_rcode, 20, "NXRRSET");
                break;
            case 9:
                snprintf(rr_rcode, 20, "NOTAUTH");
                break;
            case 10:
                snprintf(rr_rcode, 20, "NOTZONE");
                break;
            default:
                snprintf(rr_rcode, 20, "UNKNOWN-ERROR-%d", rcode);
                break;
        }
    }

    jdata = json_object();

    /* Print timestamp(s) */
    if (outputconfig.fieldsf & FIELD_TIMESTAMP_S) {
        json_timestamp_s = json_integer(l->last_seen.tv_sec);
        json_object_set(jdata, JSON_TIMESTAMP_S, json_timestamp_s);
        json_decref(json_timestamp_s);
    }

    /* Print timestamp(ms) */
    if (outputconfig.fieldsf & FIELD_TIMESTAMP_MS) {
        json_timestamp_ms = json_integer(l->last_seen.tv_usec);
        json_object_set(jdata, JSON_TIMESTAMP_MS, json_timestamp_ms);
        json_decref(json_timestamp_ms);
    }

    /* Print client IP */
    if (outputconfig.fieldsf & FIELD_CLIENT) {
        json_client = json_string(ip_addr_c);
        json_object_set(jdata, JSON_CLIENT, json_client);
        json_decref(json_client);
    }

    /* Print server IP */
    if (outputconfig.fieldsf & FIELD_SERVER) {
        json_server = json_string(ip_addr_s);
        json_object_set(jdata, JSON_SERVER, json_server);
        json_decref(json_server);
    }

    /* Print class */
    if (outputconfig.fieldsf & FIELD_CLASS) {
        json_class = json_string(rr_class);
        json_object_set(jdata, JSON_CLASS, json_class);
        json_decref(json_class);
    }

    /* Print query */
    if (outputconfig.fieldsf & FIELD_QUERY) {
        json_query = json_string((const char *)l->qname);
        json_object_set(jdata, JSON_QUERY, json_query);
        json_decref(json_query);
    }

    /* Print type */
    if (outputconfig.fieldsf & FIELD_TYPE) {
        json_type = json_string(rr_type);
        json_object_set(jdata, JSON_TYPE, json_type);
        json_decref(json_type);
    }

    if (is_err_record) {
        /* Print answer */
        if (outputconfig.fieldsf & FIELD_ANSWER) {
            json_answer = json_string(rr_rcode);
            json_object_set(jdata, JSON_ANSWER, json_answer);
            json_decref(json_answer);
        }

        /* Print TTL */
        if (outputconfig.fieldsf & FIELD_TTL) {
            json_ttl = json_integer(PASSET_ERR_TTL);
            json_object_set(jdata, JSON_TTL, json_ttl);
            json_decref(json_ttl);
        }

        /* Print count */
        if (outputconfig.fieldsf & FIELD_COUNT) {
            json_count = json_integer(PASSET_ERR_COUNT);
            json_object_set(jdata, JSON_COUNT, json_count);
            json_decref(json_count);
        }
    }
    else {
        /* Print answer */
        if (outputconfig.fieldsf & FIELD_ANSWER) {
            json_answer = json_string((const char *)p->answer);
            json_object_set(jdata, JSON_ANSWER, json_answer);
            json_decref(json_answer);
        }

        /* Print TTL */
        if (outputconfig.fieldsf & FIELD_TTL) {
            json_ttl = json_integer(p->rr->_ttl);
            json_object_set(jdata, JSON_TTL, json_ttl);
            json_decref(json_ttl);
        }

        /* Print count */
        if (outputconfig.fieldsf & FIELD_COUNT) {
            json_count = json_integer(p->seen);
            json_object_set(jdata, JSON_COUNT, json_count);
            json_decref(json_count);
        }
    }

    output = json_dumps(jdata, data_flags);
    json_decref(jdata);
    if (output != NULL) {
        /* Print to log file */
        if (fd) {
            fprintf(fd, "%s\n", output);
            fflush(fd);
        }
        
        free(output);
    }

    free(rr_class);
    free(rr_type);
    free(rr_rcode);

}
