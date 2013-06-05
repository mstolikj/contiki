/**
 * \addtogroup uip
 * @{
 */

/**
 * \defgroup uipdns uIP hostname resolver functions
 * @{
 *
 * The uIP DNS resolver functions are used to lookup a hostname and
 * map it to a numerical IP address. It maintains a list of resolved
 * hostnames that can be queried with the resolv_lookup()
 * function. New hostnames can be resolved using the resolv_query()
 * function.
 *
 * The event resolv_event_found is posted when a hostname has been
 * resolved. It is up to the receiving process to determine if the
 * correct hostname has been found by calling the resolv_lookup()
 * function with the hostname.
 */

/**
 * \file
 *         DNS host name to IP address resolver.
 * \author Adam Dunkels <adam@dunkels.com>
 * \author Robert Quattlebaum <darco@deepdarc.com>
 * \author Richard P.H.F.M Verhoeven <P.H.F.M.Verhoeven@tue.nl>
 * \author Milosh Stolikj <m.stolikj@tue.nl>
 *  *
 *         This file implements a DNS host name to IP address resolver,
 *         as well as an MDNS responder and resolver.
 */

/*
 * Copyright (c) 2002-2003, Adam Dunkels.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS
 * OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY
 * DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE
 * GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS
 * INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING
 * NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS
 * SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * This file is part of the uIP TCP/IP stack.
 *
 *
 */

#include "net/tcpip.h"
#include "net/resolv.h"
#include "net/uip-udp-packet.h"
#include "lib/random.h"

#ifndef DEBUG
#define DEBUG CONTIKI_TARGET_COOJA
#endif

#if UIP_UDP

#include <string.h>
#include <stdio.h>
#include <ctype.h>

#ifndef NULL
#define NULL (void *)0
#endif /* NULL */

#if !defined(__SDCC) && defined(SDCC_REVISION)
#define __SDCC 1
#endif

#if VERBOSE_DEBUG
#define DEBUG_PRINTF(...) printf(__VA_ARGS__)
#else
#define DEBUG_PRINTF(...) do { } while(0)
#endif

#if DEBUG || VERBOSE_DEBUG
#define PRINTF(...) printf(__VA_ARGS__)
#else
#define PRINTF(...) do { } while(0)
#endif

#ifdef __SDCC
static int
strncasecmp(const char *s1, const char *s2, size_t n)
{
  /* TODO: Add case support! */
  return strncmp(s1, s2, n);
}
static int
strcasecmp(const char *s1, const char *s2)
{
  /* TODO: Add case support! */
  return strcmp(s1, s2);
}
#endif /* __SDCC */

#define UIP_UDP_BUF ((struct uip_udpip_hdr *)&uip_buf[UIP_LLH_LEN])

/* If RESOLV_CONF_SUPPORTS_MDNS is set, then queries
 * for domain names in the local TLD will use mDNS as
 * described by draft-cheshire-dnsext-multicastdns.
 */
#ifndef RESOLV_CONF_SUPPORTS_MDNS
#define RESOLV_CONF_SUPPORTS_MDNS 1
#endif

#ifndef RESOLV_CONF_MDNS_INCLUDE_GLOBAL_V6_ADDRS
#define RESOLV_CONF_MDNS_INCLUDE_GLOBAL_V6_ADDRS 0
#endif

/** The maximum number of retries when asking for a name. */
#ifndef RESOLV_CONF_MAX_RETRIES
#define RESOLV_CONF_MAX_RETRIES 4
#endif

#ifndef RESOLV_CONF_MAX_MDNS_RETRIES
#define RESOLV_CONF_MAX_MDNS_RETRIES 3
#endif

#ifdef RESOLV_CONF_AUTO_REMOVE_TRAILING_DOTS
#define RESOLV_AUTO_REMOVE_TRAILING_DOTS RESOLV_CONF_AUTO_REMOVE_TRAILING_DOTS
#else
#define RESOLV_AUTO_REMOVE_TRAILING_DOTS RESOLV_CONF_SUPPORTS_MDNS
#endif

#ifdef RESOLV_CONF_VERIFY_ANSWER_NAMES
#define RESOLV_VERIFY_ANSWER_NAMES RESOLV_CONF_VERIFY_ANSWER_NAMES
#else
#define RESOLV_VERIFY_ANSWER_NAMES RESOLV_CONF_SUPPORTS_MDNS
#endif

#ifdef RESOLV_CONF_SUPPORTS_RECORD_EXPIRATION
#define RESOLV_SUPPORTS_RECORD_EXPIRATION RESOLV_CONF_SUPPORTS_RECORD_EXPIRATION
#else
#define RESOLV_SUPPORTS_RECORD_EXPIRATION 1
#endif

#if RESOLV_CONF_SUPPORTS_MDNS && !RESOLV_VERIFY_ANSWER_NAMES
#error RESOLV_CONF_SUPPORTS_MDNS cannot be set without RESOLV_CONF_VERIFY_ANSWER_NAMES
#endif

#if !defined(CONTIKI_TARGET_NAME) && defined(BOARD)
#define stringy2(x) #x
#define stringy(x)  stringy2(x)
#define CONTIKI_TARGET_NAME stringy(BOARD)
#endif

#ifndef CONTIKI_CONF_DEFAULT_HOSTNAME
#ifdef CONTIKI_TARGET_NAME
#define CONTIKI_CONF_DEFAULT_HOSTNAME "contiki-"CONTIKI_TARGET_NAME
#else
#define CONTIKI_CONF_DEFAULT_HOSTNAME "contiki"
#endif
#endif

#define DNS_TYPE_A      1
#define DNS_TYPE_CNAME  5
#define DNS_TYPE_PTR   12
#define DNS_TYPE_MX    15
#define DNS_TYPE_TXT   16
#define DNS_TYPE_AAAA  28
#define DNS_TYPE_SRV   33
#define DNS_TYPE_ANY  255
#define DNS_TYPE_NSEC  47

#if UIP_CONF_IPV6
#define NATIVE_DNS_TYPE DNS_TYPE_AAAA /* IPv6 */
#else
#define NATIVE_DNS_TYPE DNS_TYPE_A    /* IPv4 */
#endif

#define DNS_CLASS_IN    1
#define DNS_CLASS_ANY 255

#ifndef DNS_PORT
#define DNS_PORT 53
#endif

#ifndef MDNS_PORT
#define MDNS_PORT 5353
#endif

#ifndef MDNS_RESPONDER_PORT
#define MDNS_RESPONDER_PORT 5354
#endif

/** \internal The DNS message header. */
struct dns_hdr {
  uint16_t id;
  uint8_t flags1, flags2;
#define DNS_FLAG1_RESPONSE        0x80
#define DNS_FLAG1_OPCODE_STATUS   0x10
#define DNS_FLAG1_OPCODE_INVERSE  0x08
#define DNS_FLAG1_OPCODE_STANDARD 0x00
#define DNS_FLAG1_AUTHORATIVE     0x04
#define DNS_FLAG1_TRUNC           0x02
#define DNS_FLAG1_RD              0x01
#define DNS_FLAG2_RA              0x80
#define DNS_FLAG2_ERR_MASK        0x0f
#define DNS_FLAG2_ERR_NONE        0x00
#define DNS_FLAG2_ERR_NAME        0x03
  uint16_t numquestions;
  uint16_t numanswers;
  uint16_t numauthrr;
  uint16_t numextrarr;
};

#define RESOLV_ENCODE_INDEX(i) (uip_htons(i+1))
#define RESOLV_DECODE_INDEX(i) (unsigned char)(uip_ntohs(i-1))

/** These default values for the DNS server are Google's public DNS:
 *  <https://developers.google.com/speed/public-dns/docs/using>
 */
static uip_ipaddr_t resolv_default_dns_server =
#if UIP_CONF_IPV6
  { { 0x20, 0x01, 0x48, 0x60, 0x48, 0x60, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x88, 0x88 } };
#else /* UIP_CONF_IPV6 */
  { { 8, 8, 8, 8 } };
#endif /* UIP_CONF_IPV6 */

/** \internal The DNS answer message structure. */
struct dns_answer {
  /* DNS answer record starts with either a domain name or a pointer
   * to a name already present somewhere in the packet. */
  uint16_t type;
  uint16_t class;
  uint16_t ttl[2];
  uint16_t len;
#if UIP_CONF_IPV6
  uint8_t ipaddr[16];
#else
  uint8_t ipaddr[4];
#endif
};

struct namemap {
#define STATE_UNUSED 0
#define STATE_ERROR  1
#define STATE_NEW    2
#define STATE_ASKING 3
#define STATE_DONE   4
  uint8_t state;
  uint8_t tmr;
  uint8_t retries;
  uint8_t seqno;
#if RESOLV_SUPPORTS_RECORD_EXPIRATION
  unsigned long expiration;
#endif /* RESOLV_SUPPORTS_RECORD_EXPIRATION */
  uip_ipaddr_t ipaddr;
  uint8_t err;
#if RESOLV_CONF_SUPPORTS_MDNS
  int is_mdns:1, is_probe:1;
#endif
  char name[RESOLV_CONF_MAX_DOMAIN_NAME_SIZE + 1];
};

#ifndef UIP_CONF_RESOLV_ENTRIES
#define RESOLV_ENTRIES 4
#else /* UIP_CONF_RESOLV_ENTRIES */
#define RESOLV_ENTRIES UIP_CONF_RESOLV_ENTRIES
#endif /* UIP_CONF_RESOLV_ENTRIES */

static struct namemap names[RESOLV_ENTRIES];

#define RESOLV_PARTIAL_MATCH 1
#define RESOLV_FULL_MATCH 0

#ifndef RESOLV_CONF_SUPPORTS_DNS_SD
#define RESOLV_CONF_SUPPORTS_DNS_SD 1
#endif

#if RESOLV_CONF_SUPPORTS_DNS_SD

#ifndef DNS_SD_DEFAULT_TTL
#define DNS_SD_DEFAULT_TTL 120
#endif

#ifndef DNS_SD_FLAG_USED
#define DNS_SD_FLAG_USED 1<<15
#endif

#ifndef DNS_SD_FLAG_NEW
#define DNS_SD_FLAG_NEW 1<<14
#endif

#ifndef DNS_SD_FLAG_PURGE
#define DNS_SD_FLAG_PURGE 1<<13
#endif

#ifndef DNS_SD_FLAG_REQ
#define DNS_SD_FLAG_REQ 1<<12
#endif

#ifndef DNS_SD_FLAG_SRV
#define DNS_SD_FLAG_SRV 1<<11
#endif

#ifndef DNS_SD_FLAG_TXT
#define DNS_SD_FLAG_TXT 1<<10
#endif

#ifndef DNS_SD_FLAG_PTR
#define DNS_SD_FLAG_PTR 1<<9
#endif

#ifndef DNS_SD_FLAG_ADDR
#define DNS_SD_FLAG_ADDR 1<<8
#endif

#ifndef RESOLV_CONF_DNS_SD_ENTRIES
#define RESOLV_CONF_DNS_SD_ENTRIES 4
#endif
#ifndef RESOLV_CONF_LOCAL_SERVICE_ENTRIES
#define RESOLV_CONF_LOCAL_SERVICE_ENTRIES 4
#endif

struct resolv_local_service_t
{
  const char *name;
  uint16_t port;
  uint16_t priority;
  uint16_t weight;
  const char *txt;
  const char *ptr;
  uint16_t ptr_length;
  const char* common_suffix;
  uip_ipaddr_t *ipaddr;
  uint16_t flags;
  unsigned long expiration;
};

static struct service_resolv_entry_t service_resolv_cache[RESOLV_CONF_DNS_SD_ENTRIES];

static struct resolv_local_service_t service_list[RESOLV_CONF_LOCAL_SERVICE_ENTRIES];
#endif

static uint8_t seqno;

static struct uip_udp_conn *resolv_conn = NULL;

static struct etimer retry;

process_event_t resolv_event_found;

PROCESS(resolv_process, "DNS resolver");

static void resolv_found(char *name, uip_ipaddr_t * ipaddr);

enum {
  EVENT_NEW_SERVER = 0
};

/** \internal The DNS question message structure. */
struct dns_question {
  uint16_t type;
  uint16_t class;
};

#if RESOLV_CONF_SUPPORTS_MDNS
static char resolv_hostname[RESOLV_CONF_MAX_DOMAIN_NAME_SIZE + 1];

enum {
  MDNS_STATE_WAIT_BEFORE_PROBE,
  MDNS_STATE_PROBING,
  MDNS_STATE_READY,
};

static uint8_t mdns_state;

static const uip_ipaddr_t resolv_mdns_addr =
#if UIP_CONF_IPV6
  { { 0xff, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
      0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xfb } };
#include "net/uip-ds6.h"
#else  /* UIP_CONF_IPV6 */
  { { 224, 0, 0, 251 } };
#endif /* UIP_CONF_IPV6 */
static int mdns_needs_host_announce;

PROCESS(mdns_probe_process, "mDNS probe");
#endif /* RESOLV_CONF_SUPPORTS_MDNS */

/*---------------------------------------------------------------------------*/
#if RESOLV_VERIFY_ANSWER_NAMES || VERBOSE_DEBUG
/** \internal
 * \brief Decodes a DNS name from the DNS format into the given string.
 * \return 1 upon success, 0 if the size of the name would be too large.
 *
 * \note `dest` must point to a buffer with at least
 *       `RESOLV_CONF_MAX_DOMAIN_NAME_SIZE+1` bytes large.
 */
static uint8_t
decode_name(const unsigned char *query, char *dest,
            const unsigned char *packet)
{
  int len = RESOLV_CONF_MAX_DOMAIN_NAME_SIZE;

  unsigned char n = *query++;

  DEBUG_PRINTF("resolver: decoding name: \"");

  while(len && n) {
    if(n & 0xc0) {
      const uint16_t offset = query[0] + ((n & ~0xC0) << 8);

      DEBUG_PRINTF("<skip-to-%d>",offset);
      query = packet + offset;
      n = *query++;
    }

    if(!n)
      break;

    for(; n; --n) {
      DEBUG_PRINTF("%c",*query);

      *dest++ = *query++;

      if(!--len) {
        *dest = 0;
        return 0;
      }
    }

    n = *query++;

    if(n) {
      DEBUG_PRINTF(".");
      *dest++ = '.';
      --len;
    }
  }

  DEBUG_PRINTF("\"\n");
  *dest = 0;
  return len != 0;
}
/*---------------------------------------------------------------------------*/
/** \internal
 */
static unsigned char*
dns_name_isequal(const unsigned char *queryptr, const char *name,
                 const unsigned char *packet, int partial)
{

  if(*name == 0){
    if(partial == RESOLV_PARTIAL_MATCH){
      return queryptr;
    }else{
      return 0;
    }
  }
  unsigned char n = *queryptr++;

  while(n) {
    if(n & 0xc0) {
      queryptr = packet + queryptr[0] + ((n & ~0xC0) << 8);
      n = *queryptr++;
    }

    for(; n; --n) {
      if(!*name) {
        return 0;
      }

      if(tolower(*name++) != tolower(*queryptr++)) {
        return 0;
      }
    }
    if(partial == RESOLV_PARTIAL_MATCH && *name == 0)
      return queryptr;

    n = *queryptr++;

    if((n != 0) && (*name++ != '.')) {
      return 0;
    }
  }

  if(*name == '.')
    ++name;

  return ( name[0]==0 ? queryptr : 0 );
}
#endif /* RESOLV_VERIFY_ANSWER_NAMES */
/*---------------------------------------------------------------------------*/
/** \internal
 */
static unsigned char *
skip_name(unsigned char *query)
{
  unsigned char n;

  DEBUG_PRINTF("resolver: skip name: ");

  do {
    n = *query;
    if(n & 0xc0) {
      DEBUG_PRINTF("<skip-to-%d>", query[0] + ((n & ~0xC0) << 8));
      ++query;
      break;
    }

    ++query;

    while(n > 0) {
      DEBUG_PRINTF("%c", *query);
      ++query;
      --n;
    };
    DEBUG_PRINTF(".");
  } while(*query != 0);
  DEBUG_PRINTF("\n");
  return query + 1;
}
/*---------------------------------------------------------------------------*/
/** \internal
 */
static unsigned char *
encode_name(unsigned char *query, const char *nameptr)
{
  char *nptr;
  --nameptr;
  /* Convert hostname into suitable query format. */
  do {
    uint8_t n = 0;

    ++nameptr;
    nptr = (char *)query;
    ++query;
    for(n = 0; *nameptr != '.' && *nameptr != 0; ++nameptr) {
      *query = *nameptr;
      ++query;
      ++n;
    }
    *nptr = n;
  } while(*nameptr != 0);

  /* End the the name. */
  *query++ = 0;

  return query;
}
/*---------------------------------------------------------------------------*/
#if RESOLV_CONF_SUPPORTS_DNS_SD

static struct DNS_SD_SRV_rr_t {
  uint16_t priority;
  uint16_t weight;
  uint16_t port;
} srv_rr_fields;

/* To reduce the code adding an RR to a packet. */
static const struct {
  uint16_t rr_type;
  uint16_t class;
  uint16_t ttl_high;
  uint16_t ttl_low;
} dns_sd_default_RR = {
  UIP_HTONS(DNS_TYPE_PTR),
  UIP_HTONS(DNS_CLASS_IN | 0x8000),  /* CACHE_FLUSH */
  UIP_HTONS((DNS_SD_DEFAULT_TTL)>>16),
  UIP_HTONS((DNS_SD_DEFAULT_TTL)&0xffff)
};
/* After copying dns_sd_default_RR into a packet, set the byte
 * at the following offset to the correct record type.
 */
#define DNS_SD_TYPE_OFFSET 1

#define DNS_SD_ADD_RR(BUFFER, RR_TYPE) do {			\
    memcpy(BUFFER, &dns_sd_default_RR, sizeof(dns_sd_default_RR)); \
    BUFFER[DNS_SD_TYPE_OFFSET] = RR_TYPE; \
    BUFFER += sizeof(dns_sd_default_RR); \
  } while (0)

/* \internal
 * \brief Create a complete DNS_SD packet, including the header.
 *
 * \param sli is a pointer to an entry in the local service table.
 * \param response point to a sufficiently large buffer.
 * \param length is the size of the available buffer.
 * \param flags indicates which RRs are requested for (TXT, PTR, SRV, AAAA)
 */
static int
dns_sd_write_service(struct resolv_local_service_t* sli,
    unsigned char *response, int length, int flags)
{
  int long_name_offset = 0, suffix_offset = 0, local_offset = 0,
      hostname_offset = 0;
  unsigned char* pos;
  uint32_t ttl = UIP_HTONL(DNS_SD_DEFAULT_TTL);
  uint16_t len;
  unsigned char *rec_length;

  /* TODO: Esstimate the size of the packet to be generated, and check if
   * it fits in the buffer*/
  if (length < 40)
    return 0;
  /* add DNS header. NOTE: possible alignment issue */
  struct dns_hdr *hdr = (struct dns_hdr *) response;

  /* Zero out the header */
  memset((void *) hdr, 0, sizeof(*hdr));

  hdr->flags1 |= DNS_FLAG1_RESPONSE | DNS_FLAG1_AUTHORATIVE;
  hdr->numanswers = uip_htons(
      (flags & DNS_SD_FLAG_TXT ? 1 : 0) + (flags & DNS_SD_FLAG_SRV ? 1 : 0)
          + (flags & DNS_SD_FLAG_PTR ? 1 : 0) + (flags & DNS_SD_FLAG_ADDR ? 1 : 0));

  pos = response + sizeof(struct dns_hdr);

  /* For filling a DNS-SD service description, the prefered order of
   ** RR answers would be:
   * PTR:    map the query for a service type to a service instance name
   * SRV:    map the service instance to hostname and port (+weight+priority)
   * TXT:    specify the arguments to the service
   * A/AAAA: provide the address of the hostname mentioned in SRV.
   * This is also the order in with the DNS-SD protocol would receive them.
   *
   * In advertisements, provide them in this order to ease processing.
   */
  if (flags & DNS_SD_FLAG_PTR)
    {
      if (*sli->ptr != 0)
        {
          pos = encode_name(pos, sli->ptr);
          pos--;
        }
        {
          suffix_offset = pos - response;
          pos = encode_name(pos, sli->common_suffix);
          if (!strcasecmp(pos - 7, "\005local"))
            {
              local_offset = pos - 7 - response;
            }
        }
      DNS_SD_ADD_RR(pos, DNS_TYPE_PTR);
        {
          uint16_t len = strlen(sli->name) + 3;
          *pos++ = len >> 8;
          *pos++ = len & 0xff;
          long_name_offset = pos - response;
          *pos++ = len - 3;
          /* Name might contain '.' */
          strcpy(pos, sli->name);
          pos += len - 3;
          *pos++ = 0xc0 | (suffix_offset >> 8);
          *pos++ = suffix_offset & 0xff;
        }
    }
  if (flags & DNS_SD_FLAG_SRV)
    {
      if (long_name_offset)
        {
          /* reference */
          *pos++ = 0xc0 | (long_name_offset >> 8);
          *pos++ = long_name_offset & 0xff;
        }
      else
        {
          long_name_offset = pos - response;
          len = strlen(sli->name);
          *pos++ = len;
          //    pos = encode_name(pos, sli->name);
          strcpy(pos, sli->name);
          pos += len;
          suffix_offset = pos - response;
          pos = encode_name(pos, sli->common_suffix);

          /* .local. is probably in the name. Set local_offset as well. */
          if (!strcasecmp(pos - 7, "\005local"))
            {
              local_offset = pos - 7 - response;
            }
        }
      DNS_SD_ADD_RR(pos, DNS_TYPE_SRV);
      /* length of RR */
      rec_length = pos;
      pos += 2;
      srv_rr_fields.priority = uip_htons(sli->priority);
      srv_rr_fields.weight = uip_htons(sli->weight);
      srv_rr_fields.port = uip_htons(sli->port);
      memcpy(pos, &srv_rr_fields, sizeof(srv_rr_fields));
      pos += sizeof(srv_rr_fields);
      hostname_offset = pos - response;
      pos = encode_name(pos, resolv_hostname);
      if (!strcasecmp(pos - 7, "\005local"))
        {
          /* compression */
          pos -= 7;
          *pos++ = 0xc0 | (local_offset >> 8);
          *pos++ = (local_offset & 0xff);
        }
      uint16_t len = pos - rec_length - 2;
      *rec_length++ = len >> 8;
      *rec_length++ = len & 0xff;
    }
  if (flags & DNS_SD_FLAG_TXT)
    {
      /* assume TXT is always send together with SRV */
      *pos++ = 0xc0 | (long_name_offset >> 8);
      *pos++ = (long_name_offset & 0xff);

      DNS_SD_ADD_RR(pos, DNS_TYPE_TXT);
      /* NOTE: according to the DNS-SD specification, the TXT record can
       *       contain arbitrary binary data. Due to strlen(), we
       *       don't support '\0' within the data fields.
       *       To fix this, store the length of the txt field during service
       *       registration and use memcpy().
       */
      uint16_t len = strlen(sli->txt);
      *pos++ = len >> 8;
      *pos++ = len & 0xff;
      strncpy(pos, sli->txt, len);
      pos += len;
    }
  if (flags & DNS_SD_FLAG_ADDR)
    {
      /* Reuse mDNS code */
      if (hostname_offset)
        {
          *pos++ = 0xc0 | (hostname_offset >> 8);
          *pos++ = hostname_offset & 0xff;
        }
      else
        {
          pos = encode_name(pos, resolv_hostname);
        }
      DNS_SD_ADD_RR(pos, NATIVE_DNS_TYPE);
      *pos++ = 0;
      *pos++ = sizeof(uip_ipaddr_t);
      uip_ipaddr_copy((uip_ipaddr_t*)pos, sli->ipaddr);
      pos += sizeof(uip_ipaddr_t);
    }
  return pos - response;
}

#endif

#if RESOLV_CONF_SUPPORTS_MDNS
/** \internal
 */
static void
mdns_announce_requested(void)
{
  mdns_needs_host_announce = 1;
}
/*---------------------------------------------------------------------------*/
/** \internal
 */
static void
start_name_collision_check(clock_time_t after)
{
  process_exit(&mdns_probe_process);
  process_start(&mdns_probe_process, (void *)&after);
}
/*---------------------------------------------------------------------------*/
/** \internal
 */
static unsigned char *
mdns_write_announce_records(unsigned char *queryptr, uint8_t *count)
{
  struct dns_answer *ans;

#if UIP_CONF_IPV6
  uint8_t i;

  for(i = 0; i < UIP_DS6_ADDR_NB; ++i) {
    if(uip_ds6_if.addr_list[i].isused
#if !RESOLV_CONF_MDNS_INCLUDE_GLOBAL_V6_ADDRS
       && uip_is_addr_link_local(&uip_ds6_if.addr_list[i].ipaddr)
#endif
      ) {
      if(!*count) {
        queryptr = encode_name(queryptr, resolv_hostname);
      } else {
        /* Use name compression to refer back to the first name */
        *queryptr++ = 0xc0;
        *queryptr++ = sizeof(struct dns_hdr);
      }
      ans = (struct dns_answer *)queryptr;

      *queryptr++ = (uint8_t) ((NATIVE_DNS_TYPE) >> 8);
      *queryptr++ = (uint8_t) ((NATIVE_DNS_TYPE));

      *queryptr++ = (uint8_t) ((DNS_CLASS_IN | 0x8000) >> 8);
      *queryptr++ = (uint8_t) ((DNS_CLASS_IN | 0x8000));

      *queryptr++ = 0;
      *queryptr++ = 0;
      *queryptr++ = 0;
      *queryptr++ = 120;

      *queryptr++ = 0;
      *queryptr++ = sizeof(uip_ipaddr_t);

      uip_ipaddr_copy((uip_ipaddr_t*)queryptr, &uip_ds6_if.addr_list[i].ipaddr);
      queryptr += sizeof(uip_ipaddr_t);
      ++(*count);
    }
  }
#else /* UIP_CONF_IPV6 */
  queryptr = encode_name(queryptr, resolv_hostname);
  ans = (struct dns_answer *)queryptr;
  ans->type = UIP_HTONS(NATIVE_DNS_TYPE);
  ans->class = UIP_HTONS(DNS_CLASS_IN | 0x8000);
  ans->ttl[0] = 0;
  ans->ttl[1] = UIP_HTONS(120);
  ans->len = UIP_HTONS(sizeof(uip_ipaddr_t));
  uip_gethostaddr((uip_ipaddr_t *) ans->ipaddr);
  queryptr = (unsigned char *)ans + sizeof(*ans);
  ++(*count);
#endif /* UIP_CONF_IPV6 */
  return queryptr;
}
/*---------------------------------------------------------------------------*/
/** \internal
 * Called when we need to announce ourselves
 */
static size_t
mdns_prep_host_announce_packet(void)
{
  static const struct {
    uint16_t type;
    uint16_t class;
    uint16_t ttl[2];
    uint16_t len;
    uint8_t data[8];

  } nsec_record = {
    UIP_HTONS(DNS_TYPE_NSEC),
    UIP_HTONS(DNS_CLASS_IN | 0x8000),
    { 0, UIP_HTONS(120) },
    UIP_HTONS(8),

    {
      0xc0,
      sizeof(struct dns_hdr), /* Name compression. Re-using the name of first record. */
      0x00,
      0x04,

#if UIP_CONF_IPV6
      0x00,
      0x00,
      0x00,
      0x08,
#else /* UIP_CONF_IPV6 */
      0x40,
      0x00,
      0x00,
      0x00,
#endif /* UIP_CONF_IPV6 */
    }
  };

  unsigned char *queryptr;

  uint8_t total_answers = 0;

  struct dns_answer *ans;

  /* Be aware that, unless `ARCH_DOESNT_NEED_ALIGNED_STRUCTS` is set,
   * writing directly to the uint16_t members of this struct is an error. */
  struct dns_hdr *hdr = (struct dns_hdr *)uip_appdata;

  /* Zero out the header */
  memset((void *)hdr, 0, sizeof(*hdr));

  hdr->flags1 |= DNS_FLAG1_RESPONSE | DNS_FLAG1_AUTHORATIVE;

  queryptr = (unsigned char *)uip_appdata + sizeof(*hdr);

  queryptr = mdns_write_announce_records(queryptr, &total_answers);

  /* We now need to add an NSEC record to indicate
   * that this is all there is.
   */
  if(!total_answers) {
    queryptr = encode_name(queryptr, resolv_hostname);
  } else {
    /* Name compression. Re-using the name of first record. */
    *queryptr++ = 0xc0;
    *queryptr++ = sizeof(*hdr);
  }

  memcpy((void *)queryptr, (void *)&nsec_record, sizeof(nsec_record));

  queryptr += sizeof(nsec_record);

  /* This platform might be picky about alignment. To avoid the possibility
   * of doing an unaligned write, we are going to do this manually. */
  ((uint8_t*)&hdr->numanswers)[1] = total_answers;
  ((uint8_t*)&hdr->numextrarr)[1] = 1;

  return (queryptr - (unsigned char *)uip_appdata);
}
#endif /* RESOLV_CONF_SUPPORTS_MDNS */
/*---------------------------------------------------------------------------*/
/** \internal
 * Runs through the list of names to see if there are any that have
 * not yet been queried and, if so, sends out a query.
 */
static void
check_entries(void)
{
  volatile uint8_t i;

  uint8_t *query;

  register struct dns_hdr *hdr;

  register struct namemap *namemapptr;

  for(i = 0; i < RESOLV_ENTRIES; ++i) {
    namemapptr = &names[i];
    if(namemapptr->state == STATE_NEW || namemapptr->state == STATE_ASKING) {
      etimer_set(&retry, CLOCK_SECOND / 4);
      if(namemapptr->state == STATE_ASKING) {
        if(--namemapptr->tmr == 0) {
#if RESOLV_CONF_SUPPORTS_MDNS
          if(++namemapptr->retries ==
             (namemapptr->is_mdns ? RESOLV_CONF_MAX_MDNS_RETRIES :
              RESOLV_CONF_MAX_RETRIES))
#else /* RESOLV_CONF_SUPPORTS_MDNS */
          if(++namemapptr->retries == RESOLV_CONF_MAX_RETRIES)
#endif /* RESOLV_CONF_SUPPORTS_MDNS */
          {
            /* STATE_ERROR basically means "not found". */
            namemapptr->state = STATE_ERROR;

#if RESOLV_SUPPORTS_RECORD_EXPIRATION
            /* Keep the "not found" error valid for 30 seconds */
            namemapptr->expiration = clock_seconds() + 30;
#endif /* RESOLV_SUPPORTS_RECORD_EXPIRATION */

            resolv_found(namemapptr->name, NULL);
            continue;
          }
          namemapptr->tmr = namemapptr->retries * namemapptr->retries * 3;

#if RESOLV_CONF_SUPPORTS_MDNS
          if(namemapptr->is_probe) {
            /* Probing retries are much more aggressive, 250ms */
            namemapptr->tmr = 2;
          }
#endif /* RESOLV_CONF_SUPPORTS_MDNS */
        } else {
          /* Its timer has not run out, so we move on to next
           * entry.
           */
          continue;
        }
      } else {
        namemapptr->state = STATE_ASKING;
        namemapptr->tmr = 1;
        namemapptr->retries = 0;
      }
      hdr = (struct dns_hdr *)uip_appdata;
      memset(hdr, 0, sizeof(struct dns_hdr));
      hdr->id = RESOLV_ENCODE_INDEX(i);
#if RESOLV_CONF_SUPPORTS_MDNS
      if(!namemapptr->is_mdns || namemapptr->is_probe) {
        hdr->flags1 = DNS_FLAG1_RD;
      }
      if(namemapptr->is_mdns) {
        hdr->id = 0;
      }
#else /* RESOLV_CONF_SUPPORTS_MDNS */
      hdr->flags1 = DNS_FLAG1_RD;
#endif /* RESOLV_CONF_SUPPORTS_MDNS */
      hdr->numquestions = UIP_HTONS(1);
      query = (unsigned char *)uip_appdata + sizeof(*hdr);
      query = encode_name(query, namemapptr->name);
#if RESOLV_CONF_SUPPORTS_MDNS
      if(namemapptr->is_probe) {
        *query++ = (uint8_t) ((DNS_TYPE_ANY) >> 8);
        *query++ = (uint8_t) ((DNS_TYPE_ANY));
      } else
#endif /* RESOLV_CONF_SUPPORTS_MDNS */
      {
          /* TODO: This is a quick fix to support any type of queries.
           * If only A/AAAA is being resolved, this causes unneeded
           * RR's to be sent out. Deeper integration is needed.
           * (store query type in namemap) */
//        *query++ = (uint8_t) ((NATIVE_DNS_TYPE) >> 8);
//        *query++ = (uint8_t) ((NATIVE_DNS_TYPE));
          *query++ = (uint8_t) ((DNS_TYPE_ANY) >> 8);
          *query++ = (uint8_t) ((DNS_TYPE_ANY));
      }
      *query++ = (uint8_t) ((DNS_CLASS_IN) >> 8);
      *query++ = (uint8_t) ((DNS_CLASS_IN));
#if RESOLV_CONF_SUPPORTS_MDNS
      if(namemapptr->is_mdns) {
        if(namemapptr->is_probe) {
          /* This is our conflict detection request.
           * In order to be in compliance with the MDNS
           * spec, we need to add the records we are proposing
           * to the rrauth section.
           */
          uint8_t count = 0;

          query = mdns_write_announce_records(query, &count);
          hdr->numauthrr = UIP_HTONS(count);
        }
        uip_udp_packet_sendto(resolv_conn, uip_appdata,
                              (query - (uint8_t *) uip_appdata),
                              &resolv_mdns_addr, UIP_HTONS(MDNS_PORT));

        PRINTF("resolver: (i=%d) Sent MDNS %s for \"%s\".\n", i,
               namemapptr->is_probe?"probe":"request",namemapptr->name);
      } else {
        uip_udp_packet_sendto(resolv_conn, uip_appdata,
                              (query - (uint8_t *) uip_appdata),
                              &resolv_default_dns_server, UIP_HTONS(DNS_PORT));

        PRINTF("resolver: (i=%d) Sent DNS request for \"%s\".\n", i,
               namemapptr->name);
      }
#else /* RESOLV_CONF_SUPPORTS_MDNS */
      uip_udp_packet_sendto(resolv_conn, uip_appdata,
                            (query - (uint8_t *) uip_appdata),
                            &resolv_default_dns_server, UIP_HTONS(DNS_PORT));
      PRINTF("resolver: (i=%d) Sent DNS request for \"%s\".\n", i,
             namemapptr->name);
#endif /* RESOLV_CONF_SUPPORTS_MDNS */
      break;
    }
  }
#if RESOLV_CONF_SUPPORTS_DNS_SD
  {
    struct resolv_local_service_t *sli;
    for (sli = service_list;
        sli <= &(service_list[RESOLV_CONF_LOCAL_SERVICE_ENTRIES]); sli++)
      {
        if ((sli->flags & DNS_SD_FLAG_USED) && (sli->flags & DNS_SD_FLAG_REQ))
          {
            size_t len;
            len = dns_sd_write_service(sli, uip_appdata, UIP_BUFSIZE,
                sli->flags);
            DEBUG_PRINTF("Sending out response (flags=%x, %d bytes)\n",
                sli->flags, len);
            uip_udp_packet_sendto(resolv_conn, uip_appdata, len,
                &resolv_mdns_addr, UIP_HTONS(MDNS_PORT));
            sli->flags = sli->flags & (~DNS_SD_FLAG_REQ);
            // TODO: Add brief timeout if multiple messages need to be sent.
          }
      }
  }
#endif
}

#if RESOLV_CONF_SUPPORTS_DNS_SD
/* \internal
 * \brief Marks which local services should be placed in a response to a query. *
 *
 * \param querytype type of resource being resolved.
 * \param queryptr points to the start of an query in the packet.
 * \param packet pointer to the incoming packet.
 * */
static uint16_t resolv_newdata_mark_services(int querytype,
					     unsigned char *queryptr,
					     unsigned char *packet)
{
  uint16_t found=0;
  uint16_t i;
  uint16_t flag = 0;
  unsigned char* pos;
  switch (querytype) {
  case DNS_TYPE_ANY:
    flag = DNS_SD_FLAG_SRV|DNS_SD_FLAG_TXT|DNS_SD_FLAG_PTR|DNS_SD_FLAG_ADDR;
    break;
  case DNS_TYPE_TXT:
    flag = DNS_SD_FLAG_SRV|DNS_SD_FLAG_TXT|DNS_SD_FLAG_ADDR;
    break;
  case DNS_TYPE_SRV:
    flag = DNS_SD_FLAG_SRV|DNS_SD_FLAG_TXT|DNS_SD_FLAG_ADDR;
    break;
  case DNS_TYPE_PTR:
    flag = DNS_SD_FLAG_PTR|DNS_SD_FLAG_SRV|DNS_SD_FLAG_TXT|DNS_SD_FLAG_ADDR;
    break;
  case NATIVE_DNS_TYPE:
    flag = DNS_SD_FLAG_ADDR;
    break;
  default:
    return 0;
  }
  flag |= DNS_SD_FLAG_REQ;
  {
    struct resolv_local_service_t *sli;
    for (sli=service_list; sli<=&(service_list[RESOLV_CONF_LOCAL_SERVICE_ENTRIES]); sli++) {
      if ((sli->flags&DNS_SD_FLAG_USED)){

        if(flag & DNS_SD_FLAG_PTR){
          pos = dns_name_isequal(queryptr, sli->ptr, packet, RESOLV_PARTIAL_MATCH);
          if(pos!=0 && dns_name_isequal(pos, sli->common_suffix, packet, RESOLV_FULL_MATCH)) {
                  sli->flags |= flag;
                  found++;
                  continue;
          }
        }

        if(flag & (DNS_SD_FLAG_SRV | DNS_SD_FLAG_TXT)){
          pos = dns_name_isequal(queryptr, sli->name, packet, RESOLV_PARTIAL_MATCH);
          if (pos!=0 && dns_name_isequal(pos, sli->common_suffix, packet, RESOLV_FULL_MATCH)) {
                  sli->flags |= (DNS_SD_FLAG_SRV | DNS_SD_FLAG_TXT | DNS_SD_FLAG_ADDR | DNS_SD_FLAG_REQ) & flag;
                  found++;
                  continue;
          }
        }

      }
    }
  }
  return found;
}
#endif /* RESOLV_CONF_SUPPORTS_DNS_SD */

/*---------------------------------------------------------------------------*/
/** \internal
 * Called when new UDP data arrives.
 */
static void
newdata(void)
{
  static uint8_t nquestions, nanswers, nauthrr;

  static int8_t i;

  register struct namemap *namemapptr;

  struct dns_answer *ans;

  register struct dns_hdr const *hdr = (struct dns_hdr *)uip_appdata;

  unsigned char *queryptr = (unsigned char *)hdr + sizeof(*hdr);

  const uint8_t is_request = ((hdr->flags1 & ~1) == 0) && (hdr->flags2 == 0);

#if RESOLV_CONF_SUPPORTS_DNS_SD
  uint8_t nservices, j, mdns_cache_index, dns_sd_cache_index;;
  unsigned char* offset;
  nservices=0;
  mdns_cache_index = RESOLV_ENTRIES; dns_sd_cache_index = RESOLV_CONF_DNS_SD_ENTRIES;
#endif

  /* We only care about the question(s) and the answers. The authrr
   * and the extrarr are simply discarded.
   */
  nquestions = (uint8_t) uip_ntohs(hdr->numquestions);
  nanswers = (uint8_t) uip_ntohs(hdr->numanswers);

  queryptr = (unsigned char *)hdr + sizeof(*hdr);
  i = 0;

  DEBUG_PRINTF
    ("resolver: flags1=0x%02X flags2=0x%02X nquestions=%d, nanswers=%d, nauthrr=%d, nextrarr=%d\n",
     hdr->flags1, hdr->flags2, (uint8_t) nquestions, (uint8_t) nanswers,
     (uint8_t) uip_ntohs(hdr->numauthrr),
     (uint8_t) uip_ntohs(hdr->numextrarr));

  if(is_request && (nquestions == 0)) {
    /* Skip requests with no questions. */
    DEBUG_PRINTF("resolver: Skipping request with no questions.\n");
    return;
  }

/** QUESTION HANDLING SECTION ************************************************/

  for(; nquestions > 0;
      queryptr = skip_name(queryptr) + sizeof(struct dns_question),
      --nquestions
  ) {
#if RESOLV_CONF_SUPPORTS_MDNS
    if(!is_request) {
      /* If this isn't a request, we don't need to bother
       * looking at the individual questions. For the most
       * part, this loop to just used to skip past them.
       */
      continue;
    }

    {
      struct dns_question *question = (struct dns_question *)skip_name(queryptr);

#if !ARCH_DOESNT_NEED_ALIGNED_STRUCTS
      static struct dns_question aligned;
      memcpy(&aligned, question, sizeof(aligned));
      question = &aligned;
#endif /* !ARCH_DOESNT_NEED_ALIGNED_STRUCTS */

      DEBUG_PRINTF("resolver: Question %d: type=%d class=%d\n", ++i,
                   uip_htons(question->type), uip_htons(question->class));

      if(((uip_ntohs(question->class) & 0x7FFF) != DNS_CLASS_IN) ||
         ((question->type != UIP_HTONS(DNS_TYPE_ANY)) &&
#if RESOLV_CONF_SUPPORTS_DNS_SD
	  (question->type != UIP_HTONS(DNS_TYPE_TXT)) &&
	  (question->type != UIP_HTONS(DNS_TYPE_SRV)) &&
	  (question->type != UIP_HTONS(DNS_TYPE_PTR)) &&
#endif /* RESOLV_CONF_SUPPORTS_DNS_SD */
          (question->type != UIP_HTONS(NATIVE_DNS_TYPE)))) {
        /* Skip unrecognised records. */
        continue;
      }
#if RESOLV_CONF_SUPPORTS_DNS_SD
      /* Check whether the query matches any of the local services. */
      nservices += resolv_newdata_mark_services(uip_ntohs(question->type),
						queryptr, uip_appdata);
#endif /* RESOLV_CONF_SUPPORTS_DNS_SD */

      if(!dns_name_isequal(queryptr, resolv_hostname, uip_appdata, RESOLV_FULL_MATCH)) {
        continue;
      }

      PRINTF("resolver: THIS IS A REQUEST FOR US!!!\n");

      if(mdns_state == MDNS_STATE_READY) {
        /* We only send immediately if this isn't an MDNS request.
         * Otherwise, we schedule ourselves to send later.
         */
        if(UIP_UDP_BUF->srcport == UIP_HTONS(MDNS_PORT)) {
          mdns_announce_requested();
        } else {
          uip_udp_packet_sendto(resolv_conn, uip_appdata,
                                mdns_prep_host_announce_packet(),
                                &UIP_UDP_BUF->srcipaddr,
                                UIP_UDP_BUF->srcport);
        }
#if RESOLV_CONF_SUPPORTS_DNS_SD
	/* The other queries might be service related.
	 * Process them as well.  It is not clear whether the
	 * uip_udp_packet_sendto() might overwrite the DNS packet
	 * that is currently being processed.
	 */
	continue;
#else
        return;
#endif 
      } else {
        PRINTF("resolver: But we are still probing. Waiting...\n");
        /* We are still probing. We need to do the mDNS
         * probe race condition check here and make sure
         * we don't need to delay probing for a second.
         */
        nauthrr = (uint8_t)uip_ntohs(hdr->numauthrr);

        /* For now, we will always restart the collision check if
         * there are *any* authority records present.
         * In the future we should follow the spec more closely,
         * but this should eventually converge to something reasonable.
         */
        if(nauthrr) {
          start_name_collision_check(CLOCK_SECOND);
        }
      }
    }
#endif /* RESOLV_CONF_SUPPORTS_MDNS */
  }

/** ANSWER HANDLING SECTION **************************************************/

  if(nanswers == 0) {
    /* Skip responses with no answers. */
    return;
  }

#if RESOLV_CONF_SUPPORTS_MDNS
  if(UIP_UDP_BUF->srcport == UIP_HTONS(MDNS_PORT) &&
     hdr->id == 0) {
    /* OK, this was from MDNS. Things get a little weird here,
     * because we can't use the `id` field. We will look up the
     * appropriate request in a later step. */

    i = -1;
    namemapptr = NULL;
  } else
#endif /* RESOLV_CONF_SUPPORTS_MDNS */
  {
    /* The ID in the DNS header should be our entry into the name table. */
    i = RESOLV_DECODE_INDEX(hdr->id);

    namemapptr = &names[i];

    if(i >= RESOLV_ENTRIES || i < 0 || namemapptr->state != STATE_ASKING) {
      PRINTF("resolver: DNS response has bad ID (%04X) \n", uip_ntohs(hdr->id));
      return;
    }

    PRINTF("resolver: Incoming response for \"%s\".\n", namemapptr->name);

    /* We'll change this to DONE when we find the record. */
    namemapptr->state = STATE_ERROR;

    namemapptr->err = hdr->flags2 & DNS_FLAG2_ERR_MASK;

#if RESOLV_SUPPORTS_RECORD_EXPIRATION
    /* If we remain in the error state, keep it cached for 30 seconds. */
    namemapptr->expiration = clock_seconds() + 30;
#endif /* RESOLV_SUPPORTS_RECORD_EXPIRATION */

    /* Check for error. If so, call callback to inform. */
    if(namemapptr->err != 0) {
      namemapptr->state = STATE_ERROR;
      resolv_found(namemapptr->name, NULL);
      return;
    }
  }

  i = 0;

  /* Answer parsing loop */
  while(nanswers > 0) {
    ans = (struct dns_answer *)skip_name(queryptr);

#if !ARCH_DOESNT_NEED_ALIGNED_STRUCTS
    {
      static struct dns_answer aligned;
      memcpy(&aligned, ans, sizeof(aligned));
      ans = &aligned;
    }
#endif /* !ARCH_DOESNT_NEED_ALIGNED_STRUCTS */

#if VERBOSE_DEBUG
    static char debug_name[40];
    decode_name(queryptr, debug_name, uip_appdata);
    DEBUG_PRINTF("resolver: Answer %d: \"%s\", type %d, class %d, ttl %d, length %d\n",
                 ++i, debug_name, uip_ntohs(ans->type),
                 uip_ntohs(ans->class) & 0x7FFF,
                 (int)((uint32_t) uip_ntohs(ans->ttl[0]) << 16) | (uint32_t)
                 uip_ntohs(ans->ttl[1]), uip_ntohs(ans->len));
#endif /* VERBOSE_DEBUG */

    /* Check the class of the answer to make sure
     * it matches what we are expecting
     */
    if(((uip_ntohs(ans->class) & 0x7FFF) != DNS_CLASS_IN)) {
      goto skip_to_next_answer;
    }

    if(ans->type != UIP_HTONS(NATIVE_DNS_TYPE) &&
#if RESOLV_CONF_SUPPORTS_DNS_SD
       ans->type != UIP_HTONS(DNS_TYPE_PTR) &&
       ans->type != UIP_HTONS(DNS_TYPE_TXT) &&
       ans->type != UIP_HTONS(DNS_TYPE_SRV)
#else
       ans->len != UIP_HTONS(sizeof(uip_ipaddr_t))
#endif
       ) {

      goto skip_to_next_answer;
    }

#if RESOLV_CONF_SUPPORTS_MDNS
    if(UIP_UDP_BUF->srcport == UIP_HTONS(MDNS_PORT) &&
       hdr->id == 0) {
      int8_t available_i = RESOLV_ENTRIES;

      DEBUG_PRINTF("resolver: MDNS query.\n");

      /* For MDNS, we need to actually look up the name we
       * are looking for.
       */
      for(i = 0; i < RESOLV_ENTRIES; ++i) {
        namemapptr = &names[i];
        if((namemapptr->state == STATE_UNUSED)
#if RESOLV_SUPPORTS_RECORD_EXPIRATION
	   || (namemapptr->state == STATE_DONE && clock_seconds() > namemapptr->expiration)
#endif /* RESOLV_SUPPORTS_RECORD_EXPIRATION */
	   ) {
          available_i = i;
        } else {
	  if(dns_name_isequal(queryptr, namemapptr->name, uip_appdata, RESOLV_FULL_MATCH)) {
	    break;
	  }
	}
      }
#if !RESOLV_CONF_SUPPORTS_DNS_SD
      if(i == RESOLV_ENTRIES && available_i < RESOLV_ENTRIES) {
        DEBUG_PRINTF("resolver: Unsolicited MDNS response.\n");
        i = available_i;
        namemapptr = &names[i];
        if(!decode_name(queryptr, namemapptr->name, uip_appdata)) {
          DEBUG_PRINTF("resolver: MDNS name too big to cache.\n");
          namemapptr = NULL;
          goto skip_to_next_answer;
        }
      }
#endif
#if RESOLV_CONF_SUPPORTS_DNS_SD
          if (ans->type != UIP_HTONS(NATIVE_DNS_TYPE)
              || dns_sd_cache_index != RESOLV_CONF_DNS_SD_ENTRIES)
            {
              /* The response is related to DNS_SD or the A/AAAA record follows
               * a DNS_SD related response, giving the address of a service.
               */
              /* It would be nice to move the following code into a function,
               * but the number of parameters would be quite large due to
               * alignment issues of ans and the different records.
               */
              switch (ans->type)
                {
              case UIP_HTONS(DNS_TYPE_PTR):
                if (i == RESOLV_ENTRIES) /* It is a PTR record, and we have not asked for it. */
                  goto skip_to_next_answer;

                mdns_cache_index = i;
                dns_sd_cache_index = RESOLV_CONF_DNS_SD_ENTRIES;

                /* We have asked for it. Check if an entry like this is already in the local cache. */
                offset = (unsigned char*) skip_name(queryptr) + 10;

                for (j = 0; j < RESOLV_CONF_DNS_SD_ENTRIES; ++j)
                  {
                    if ((service_resolv_cache[j].flags & DNS_SD_FLAG_USED)
                        && (dns_name_isequal(offset,
                            service_resolv_cache[j].servicename, uip_appdata,
                            RESOLV_FULL_MATCH)))
                      {
                        dns_sd_cache_index = j;
                        goto skip_to_next_answer;
                      }
                    if (!(service_resolv_cache[j].flags & DNS_SD_FLAG_USED))
                      {
                        dns_sd_cache_index = j;
                      }
                  }

                if (dns_sd_cache_index == RESOLV_CONF_DNS_SD_ENTRIES)
                  {
                    PRINTF("dns-sd: DNS-SD cache is full.\n");
                    goto skip_to_next_answer;
                  }
                service_resolv_cache[dns_sd_cache_index].queryname =
                    names[i].name;
                service_resolv_cache[dns_sd_cache_index].flags = DNS_SD_FLAG_USED;
                if (!decode_name(offset,
                    service_resolv_cache[dns_sd_cache_index].servicename,
                    uip_appdata))
                  {
                    PRINTF("dns-sd: Name cannot fit in cache!\n");
                    goto skip_to_next_answer;
                  }
                DEBUG_PRINTF(
                    "dns-sd: Resolved PTR to %s\n", service_resolv_cache[dns_sd_cache_index].servicename);
                /* Set TTL etc */
                break;
              case UIP_HTONS(DNS_TYPE_SRV):
              case UIP_HTONS(DNS_TYPE_TXT):
                /* There was no PTR before this RR in this packet. */
                if (dns_sd_cache_index == RESOLV_CONF_DNS_SD_ENTRIES)
                  {
                    /* The RR name does not match with any query. */
                    if (i == RESOLV_ENTRIES)
                      goto skip_to_next_answer;

                    /* We have asked for this particular service instance. See if it is already in the cache. */
                    for (j = 0; j < RESOLV_CONF_DNS_SD_ENTRIES; ++j)
                      {
                        if ((service_resolv_cache[j].flags & DNS_SD_FLAG_USED)
                            && (dns_name_isequal(queryptr,
                                service_resolv_cache[j].servicename,
                                uip_appdata, RESOLV_FULL_MATCH)))
                          {
                            dns_sd_cache_index = j;
                            break;
                          }
                        else if (!(service_resolv_cache[j].flags & DNS_SD_FLAG_USED))
                          {
                            dns_sd_cache_index = j;
                          }
                      }

                    if (dns_sd_cache_index == RESOLV_CONF_DNS_SD_ENTRIES)
                      {
                        PRINTF("dns-sd: DNS-SD cache is full.\n");
                        goto skip_to_next_answer;
                      }

                    if (!decode_name(queryptr,
                        service_resolv_cache[dns_sd_cache_index].servicename,
                        uip_appdata))
                      {
                        PRINTF("dns-sd: Name cannot fit in cache!\n");
                        goto skip_to_next_answer;
                      }
                    service_resolv_cache[dns_sd_cache_index].flags = DNS_SD_FLAG_USED;

                  }
                offset = (unsigned char *) skip_name(queryptr) + 10;
                /* We have a match, just fill out the rest. */
                if (ans->type == UIP_HTONS(DNS_TYPE_SRV))
                  {
                    /* SRV record */
                    service_resolv_cache[dns_sd_cache_index].priority =
                        (*(offset) << 8) + (*(offset + 1));
                    service_resolv_cache[dns_sd_cache_index].weight = (*(offset
                        + 2) << 8) + (*(offset + 3));
                    service_resolv_cache[dns_sd_cache_index].port = (*(offset
                        + 4) << 8) + (*(offset + 5));
                    offset += 6;
                    if (service_resolv_cache[dns_sd_cache_index].hostname
                        == NULL && available_i < RESOLV_ENTRIES)
                      {
                        if (!decode_name(offset, names[available_i].name,
                            uip_appdata))
                          {
                            PRINTF("dns-sd: MDNS name too big to cache.\n");
                            namemapptr = NULL;
                            /* Clean up? */
                            goto skip_to_next_answer;
                          }
                        mdns_cache_index = available_i;
                        service_resolv_cache[dns_sd_cache_index].hostname =
                            names[available_i].name;
                        service_resolv_cache[dns_sd_cache_index].ipaddr =
                            &names[available_i].ipaddr;
                      }

                    PRINTF(
                        "dns-sd: Resolved SRV (%s)\n", service_resolv_cache[dns_sd_cache_index].servicename);
                    PRINTF(
                        "dns-sd: SRV Parameters: %d %d %d\n", service_resolv_cache[dns_sd_cache_index].priority, service_resolv_cache[dns_sd_cache_index].weight, service_resolv_cache[dns_sd_cache_index].port);
                    PRINTF(
                        "dns-sd: TARGET %s\n", service_resolv_cache[dns_sd_cache_index].hostname);
                  }
                else
                  {
                    /* TXT record */
                    if (ans->len > UIP_HTONS(RESOLV_CONF_MAX_DNS_SD_TXT_SIZE))
                      {
                        PRINTF("dns-sd: Not enough room to store TXT record\n");
                        goto skip_to_next_answer;
                      }
                    strncpy(service_resolv_cache[dns_sd_cache_index].txt,
                        offset, uip_ntohs(ans->len));
                    service_resolv_cache[dns_sd_cache_index].txt[uip_ntohs(
                        ans->len)] = '\0';
                    DEBUG_PRINTF(
                        "dns-sd: Found TXT for SRV %s: %s\n", service_resolv_cache[dns_sd_cache_index].servicename, service_resolv_cache[dns_sd_cache_index].txt);
                  }
                break;

              case UIP_HTONS(NATIVE_DNS_TYPE):
                /* search service cache for hostname, set IP address. */
                if (ans->len != UIP_HTONS(sizeof(uip_ipaddr_t)))
                  {
                    goto skip_to_next_answer;
                  }
                for (i = 0; i < RESOLV_ENTRIES; ++i)
                  {
                    if (dns_name_isequal(queryptr, names[i].name, uip_appdata,
                        RESOLV_FULL_MATCH))
                      {
                        uip_ipaddr_copy(&names[i].ipaddr,
                            (uip_ipaddr_t *) ans->ipaddr);
                        names[i].state = STATE_DONE;
                        DEBUG_PRINTF("dns-sd: resolved %s\n", names[i].name);
                        goto skip_to_next_answer;
                      }
                  }
                break;
              default:
                break;
                }
              #warning Shouldnt this include the uip_ntohs and shift by 16 ?
              service_resolv_cache[dns_sd_cache_index].expiration = ans->ttl[1] + (ans->ttl[0] << 8);
              service_resolv_cache[dns_sd_cache_index].expiration += clock_seconds();

              /* Note: store TTL value as well */
              if (ans->type != UIP_HTONS(NATIVE_DNS_TYPE))
                {
                  goto skip_to_next_answer;
                }

            }
#endif

      if(i == RESOLV_ENTRIES) {
        DEBUG_PRINTF
          ("resolver: Not enough room to keep track of unsolicited MDNS answer.\n");

        if(dns_name_isequal(queryptr, resolv_hostname, uip_appdata, RESOLV_FULL_MATCH)) {
          /* Oh snap, they say they are us! We had better report them... */
          resolv_found(resolv_hostname, (uip_ipaddr_t *) ans->ipaddr);
        }
        namemapptr = NULL;
        goto skip_to_next_answer;
      }
      goto skip_to_next_answer;
      namemapptr = &names[i];

    } else
#endif /* RESOLV_CONF_SUPPORTS_MDNS */
    {
      /* This will force us to stop even if there are more answers. */
      nanswers = 1;
    }

/*  This is disabled for now, so that we don't fail on CNAME records.
#if RESOLV_VERIFY_ANSWER_NAMES
    if(namemapptr && !dns_name_isequal(queryptr, namemapptr->name, uip_appdata, RESOLV_FULL_MATCH)) {
      DEBUG_PRINTF("resolver: Answer name doesn't match question...!\n");
      goto skip_to_next_answer;
    }
#endif
*/

    DEBUG_PRINTF("resolver: Answer for \"%s\" is usable.\n", namemapptr->name);

    namemapptr->state = STATE_DONE;
#if RESOLV_SUPPORTS_RECORD_EXPIRATION
#warning Shouldnt this include the uip_ntohs and shift by 16 ?
    namemapptr->expiration = ans->ttl[1] + (ans->ttl[0] << 8);
    namemapptr->expiration += clock_seconds();
#endif /* RESOLV_SUPPORTS_RECORD_EXPIRATION */

    uip_ipaddr_copy(&namemapptr->ipaddr, (uip_ipaddr_t *) ans->ipaddr);

    resolv_found(namemapptr->name, &namemapptr->ipaddr);

  skip_to_next_answer:
    queryptr = (unsigned char *)skip_name(queryptr) + 10 + uip_htons(ans->len);
    --nanswers;
  }

#if RESOLV_CONF_SUPPORTS_DNS_SD
  /* All queries have been processed. If local services match,
   * transmit or schedule a response now.
   */
  if (nservices)
    {
      /* Force check_entires() to run on our process. */
      process_post(&resolv_process, PROCESS_EVENT_TIMER, 0);
    }
#endif /* RESOLVE_CONF_SUPPORTS_DNS_SD */
}
/*---------------------------------------------------------------------------*/
#if RESOLV_CONF_SUPPORTS_MDNS
/**
 * \brief           Changes the local hostname advertised by MDNS.
 * \param hostname  The new hostname to advertise.
 */
void
resolv_set_hostname(const char *hostname)
{
  strncpy(resolv_hostname, hostname, RESOLV_CONF_MAX_DOMAIN_NAME_SIZE);

  /* Add the .local suffix if it isn't already there */
  if(strlen(resolv_hostname) < 7 ||
     strcasecmp(resolv_hostname + strlen(resolv_hostname) - 6, ".local") != 0) {
    strncat(resolv_hostname, ".local", RESOLV_CONF_MAX_DOMAIN_NAME_SIZE);
  }

  PRINTF("resolver: hostname changed to \"%s\"\n", resolv_hostname);

  start_name_collision_check(0);
}
/*---------------------------------------------------------------------------*/
/**
 * \brief      Returns the local hostname being advertised via MDNS.
 * \return     C-string containing the local hostname.
 */
const char *
resolv_get_hostname(void)
{
  return resolv_hostname;
}
/*---------------------------------------------------------------------------*/
/** \internal
 * Process for probing for name conflicts.
 */
PROCESS_THREAD(mdns_probe_process, ev, data)
{
  static struct etimer delay;

  PROCESS_BEGIN();
  mdns_state = MDNS_STATE_WAIT_BEFORE_PROBE;

  PRINTF("mdns-probe: Process (re)started.\n");

  /* Wait extra time if specified in data */
  if(NULL != data) {
    PRINTF("mdns-probe: Probing will begin in %ld clocks.\n",
           (long)*(clock_time_t *) data);
    etimer_set(&delay, *(clock_time_t *) data);
    PROCESS_WAIT_EVENT_UNTIL(ev == PROCESS_EVENT_TIMER);
  }

  /* We need to wait a random (0-250ms) period of time before
   * probing to be in compliance with the MDNS spec. */
  etimer_set(&delay, CLOCK_SECOND * (random_rand() & 0xFF) / 1024);
  PROCESS_WAIT_EVENT_UNTIL(ev == PROCESS_EVENT_TIMER);

  /* Begin searching for our name. */
  mdns_state = MDNS_STATE_PROBING;
  resolv_query(resolv_hostname);

  do {
    PROCESS_WAIT_EVENT_UNTIL(ev == resolv_event_found);
  } while(strcasecmp(resolv_hostname, data) != 0);

  mdns_state = MDNS_STATE_READY;
  mdns_announce_requested();

  PRINTF("mdns-probe: Finished probing.\n");

  PROCESS_END();
}
#endif /* RESOLV_CONF_SUPPORTS_MDNS */
/*---------------------------------------------------------------------------*/
/** \internal
 * The main UDP function.
 */
PROCESS_THREAD(resolv_process, ev, data)
{
  PROCESS_BEGIN();

  memset(names, 0, sizeof(names));

  resolv_event_found = process_alloc_event();

  PRINTF("resolver: Process started.\n");

  resolv_conn = udp_new(NULL, 0, NULL);
  resolv_conn->rport = 0;

#if RESOLV_CONF_SUPPORTS_MDNS
  PRINTF("resolver: Supports MDNS.\n");
  uip_udp_bind(resolv_conn, UIP_HTONS(MDNS_PORT));

#if UIP_CONF_IPV6
  uip_ds6_maddr_add(&resolv_mdns_addr);
#else
  /* TODO: Is there anything we need to do here for IPv4 multicast? */
#endif

  resolv_set_hostname(CONTIKI_CONF_DEFAULT_HOSTNAME);
#endif /* RESOLV_CONF_SUPPORTS_MDNS */

  while(1) {
    PROCESS_WAIT_EVENT();

    if(ev == PROCESS_EVENT_TIMER) {
      tcpip_poll_udp(resolv_conn);
    } else if(ev == tcpip_event) {
      if(uip_udp_conn == resolv_conn) {
        if(uip_newdata()) {
          newdata();
        }
        if(uip_poll()) {
#if RESOLV_CONF_SUPPORTS_MDNS
          if(mdns_needs_host_announce) {
            size_t len;

            PRINTF("resolver: Announcing that we are \"%s\".\n",
                   resolv_hostname);

            memset(uip_appdata, 0, sizeof(struct dns_hdr));

            len = mdns_prep_host_announce_packet();

            uip_udp_packet_sendto(resolv_conn, uip_appdata,
                                  len, &resolv_mdns_addr, UIP_HTONS(MDNS_PORT));

            mdns_needs_host_announce = 0;

            /* Poll again in case this fired
             * at the same time the event timer did.
             */
            tcpip_poll_udp(resolv_conn);
          } else
#endif /* RESOLV_CONF_SUPPORTS_MDNS */
          {
            check_entries();
          }
        }
      }
    }

#if RESOLV_CONF_SUPPORTS_MDNS
    if(mdns_needs_host_announce) {
      tcpip_poll_udp(resolv_conn);
    }
#endif /* RESOLV_CONF_SUPPORTS_MDNS */
  }

  PROCESS_END();
}
/*---------------------------------------------------------------------------*/
#if RESOLV_AUTO_REMOVE_TRAILING_DOTS
static const char *
remove_trailing_dots(const char *name) {
  static char dns_name_without_dots[RESOLV_CONF_MAX_DOMAIN_NAME_SIZE + 1];
  size_t len = strlen(name);

  if(name[len - 1] == '.') {
    strncpy(dns_name_without_dots, name, sizeof(dns_name_without_dots));
    while(len && (dns_name_without_dots[len - 1] == '.')) {
      dns_name_without_dots[--len] = 0;
    }
    name = dns_name_without_dots;
  }
  return name;
}
#else /* RESOLV_AUTO_REMOVE_TRAILING_DOTS */
#define remove_trailing_dots(x) (x)
#endif /* RESOLV_AUTO_REMOVE_TRAILING_DOTS */
/*---------------------------------------------------------------------------*/
/**
 * Queues a name so that a question for the name will be sent out.
 *
 * \param name The hostname that is to be queried.
 */
void
resolv_query(const char *name)
{
  static uint8_t i;

  static uint8_t lseq, lseqi;

  register struct namemap *nameptr = 0;

  lseq = lseqi = 0;

  /* Remove trailing dots, if present. */
  name = remove_trailing_dots(name);

  for(i = 0; i < RESOLV_ENTRIES; ++i) {
    nameptr = &names[i];
    if(0 == strcasecmp(nameptr->name, name)) {
      break;
    }
    if((nameptr->state == STATE_UNUSED)
#if RESOLV_SUPPORTS_RECORD_EXPIRATION
      || (nameptr->state == STATE_DONE && clock_seconds() > nameptr->expiration)
#endif /* RESOLV_SUPPORTS_RECORD_EXPIRATION */
    ) {
      lseqi = i;
      lseq = 255;
    } else if(seqno - nameptr->seqno > lseq) {
      lseq = seqno - nameptr->seqno;
      lseqi = i;
    }
  }

  if(i == RESOLV_ENTRIES) {
    i = lseqi;
    nameptr = &names[i];
  }

  PRINTF("resolver: Starting query for \"%s\".\n", name);

  memset(nameptr, 0, sizeof(*nameptr));

  strncpy(nameptr->name, name, sizeof(nameptr->name));
  nameptr->state = STATE_NEW;
  nameptr->seqno = seqno;
  ++seqno;

#if RESOLV_CONF_SUPPORTS_MDNS
  {
    size_t name_len = strlen(name);

    static const char local_suffix[] = "local";

    if((name_len > (sizeof(local_suffix) - 1)) &&
       (0 == strcasecmp(name + name_len - (sizeof(local_suffix) - 1), local_suffix))) {
      PRINTF("resolver: Using MDNS to look up \"%s\".\n", name);
      nameptr->is_mdns = 1;
    } else {
      nameptr->is_mdns = 0;
    }
  }
  nameptr->is_probe = (mdns_state == MDNS_STATE_PROBING) &&
                      (0 == strcmp(nameptr->name, resolv_hostname));
#endif /* RESOLV_CONF_SUPPORTS_MDNS */

  /* Force check_entires() to run on our process. */
  process_post(&resolv_process, PROCESS_EVENT_TIMER, 0);
}
/*---------------------------------------------------------------------------*/
/**
 * Look up a hostname in the array of known hostnames.
 *
 * \note This function only looks in the internal array of known
 * hostnames, it does not send out a query for the hostname if none
 * was found. The function resolv_query() can be used to send a query
 * for a hostname.
 *
 */
resolv_status_t
resolv_lookup(const char *name, uip_ipaddr_t ** ipaddr)
{
  resolv_status_t ret = RESOLV_STATUS_UNCACHED;

  static uint8_t i;

  struct namemap *nameptr;

  /* Remove trailing dots, if present. */
  name = remove_trailing_dots(name);

#if UIP_CONF_LOOPBACK_INTERFACE
  if(strcmp(name, "localhost")) {
    static uip_ipaddr_t loopback =
#if UIP_CONF_IPV6
    { { 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01 } };
#else /* UIP_CONF_IPV6 */
    { { 127, 0, 0, 1 } };
#endif /* UIP_CONF_IPV6 */
    if(ipaddr) {
      *ipaddr = &loopback;
    }
    ret = RESOLV_STATUS_CACHED;
  }
#endif /* UIP_CONF_LOOPBACK_INTERFACE */

  /* Walk through the list to see if the name is in there. */
  for(i = 0; i < RESOLV_ENTRIES; ++i) {
    nameptr = &names[i];

    if(strcasecmp(name, nameptr->name) == 0) {
      switch (nameptr->state) {
      case STATE_DONE:
        ret = RESOLV_STATUS_CACHED;
#if RESOLV_SUPPORTS_RECORD_EXPIRATION
        if(clock_seconds() > nameptr->expiration) {
          ret = RESOLV_STATUS_EXPIRED;
        }
#endif /* RESOLV_SUPPORTS_RECORD_EXPIRATION */
        break;
      case STATE_NEW:
      case STATE_ASKING:
        ret = RESOLV_STATUS_RESOLVING;
        break;
      /* Almost certainly a not-found error from server */
      case STATE_ERROR:
        ret = RESOLV_STATUS_NOT_FOUND;
#if RESOLV_SUPPORTS_RECORD_EXPIRATION
        if(clock_seconds() > nameptr->expiration) {
          ret = RESOLV_STATUS_UNCACHED;
        }
#endif /* RESOLV_SUPPORTS_RECORD_EXPIRATION */
        break;
      }

      if(ipaddr) {
        *ipaddr = &nameptr->ipaddr;
      }

      /* Break out of for loop. */
      break;
    }
  }

#if VERBOSE_DEBUG
  switch (ret) {
  case RESOLV_STATUS_CACHED:{
      PRINTF("resolver: Found \"%s\" in cache.\n", name);
      const uip_ipaddr_t *addr = *ipaddr;

      DEBUG_PRINTF
        ("resolver: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x \n",
         ((uint8_t *) addr)[0], ((uint8_t *) addr)[1], ((uint8_t *) addr)[2],
         ((uint8_t *) addr)[3], ((uint8_t *) addr)[4], ((uint8_t *) addr)[5],
         ((uint8_t *) addr)[6], ((uint8_t *) addr)[7], ((uint8_t *) addr)[8],
         ((uint8_t *) addr)[9], ((uint8_t *) addr)[10],
         ((uint8_t *) addr)[11], ((uint8_t *) addr)[12],
         ((uint8_t *) addr)[13], ((uint8_t *) addr)[14],
         ((uint8_t *) addr)[15]);
      break;
    }
  default:
    DEBUG_PRINTF("resolver: \"%s\" is NOT cached.\n", name);
    break;
  }
#endif /* VERBOSE_DEBUG */

  return ret;
}

#if RESOLV_CONF_SUPPORTS_DNS_SD

resolv_status_t
resolv_lookup_service(const char *queryname,
struct service_resolv_entry_t **answer)
{
  resolv_status_t t;
  #warning resolv_lookup_service not implemented
  return t;
}

resolv_status_t
resolv_lookup_service_next(struct service_resolv_entry_t **answer)
{
  resolv_status_t t;
  #warning resolv_lookup_service_next not implemented
  return t;
}

int
resolv_add_service(const char *name, uint16_t port, uint16_t priority,
uint16_t weight, const char *txt, const char *ptr, uint16_t ptr_length,
char* common_suffix, uip_ipaddr_t* ipaddr)
{
  struct resolv_local_service_t *sli = service_list;
  int i = 0;
  while (i < RESOLV_CONF_LOCAL_SERVICE_ENTRIES && (sli->flags & DNS_SD_FLAG_USED))
  {
    sli++;
    i++;
  }
  if (i == RESOLV_CONF_LOCAL_SERVICE_ENTRIES)
  {
    return -1;
  }
  else
  {
    sli->name = name;
    sli->port = port;
    sli->priority = priority;
    sli->weight = weight;
    sli->txt = txt;
    sli->ptr = ptr;
    sli->ptr_length = ptr_length;
    sli->common_suffix = common_suffix;
    sli->flags = DNS_SD_FLAG_USED | DNS_SD_FLAG_NEW | DNS_SD_FLAG_REQ | DNS_SD_FLAG_SRV | DNS_SD_FLAG_TXT
        | DNS_SD_FLAG_PTR | DNS_SD_FLAG_ADDR;
    sli->ipaddr = ipaddr;
    sli->expiration = clock_seconds(); /* or 'now()' to start advertizing */
    return i;
  }
}

int
resolv_remove_service(const char *name)
{
  struct resolv_local_service_t *sli = service_list;
  int i = 0;
  while (i < RESOLV_CONF_LOCAL_SERVICE_ENTRIES && (sli->flags & DNS_SD_FLAG_USED)
    && (sli->name != name))
  {
    i++;
    sli++;
  }
  if (i == RESOLV_CONF_LOCAL_SERVICE_ENTRIES)
  {
    return -1;
  }
  else
  {
    /* Mark for purging, check_entries should send a packet with TTL 0. */
    sli->flags &= DNS_SD_FLAG_PURGE;
    return i;
  }
}

#endif


/*---------------------------------------------------------------------------*/
/**
 * Obtain the currently configured DNS server.
 *
 * \return A pointer to a 4-byte representation of the IP address of
 * the currently configured DNS server or NULL if no DNS server has
 * been configured.
 */
uip_ipaddr_t *
resolv_getserver(void)
{
  return &resolv_default_dns_server;
}
/*---------------------------------------------------------------------------*/
/**
 * Configure a DNS server.
 *
 * \param dnsserver A pointer to a 4-byte representation of the IP
 * address of the DNS server to be configured.
 */
void
resolv_conf(const uip_ipaddr_t * dnsserver)
{
  uip_ipaddr_copy(&resolv_default_dns_server, dnsserver);
  process_post(&resolv_process, EVENT_NEW_SERVER, &resolv_default_dns_server);
}
/*---------------------------------------------------------------------------*/
/** \internal
 * Callback function which is called when a hostname is found.
 *
 */
static void
resolv_found(char *name, uip_ipaddr_t * ipaddr)
{
#if RESOLV_CONF_SUPPORTS_MDNS
  if(strncasecmp(resolv_hostname, name, strlen(resolv_hostname)) == 0 &&
     ipaddr
#if UIP_CONF_IPV6
     && !uip_ds6_is_my_addr(ipaddr)
#else
     && uip_ipaddr_cmp(&uip_hostaddr, ipaddr) != 0
#endif
    ) {
    uint8_t i;

    if(mdns_state == MDNS_STATE_PROBING) {
      /* We found this new name while probing.
       * We must now rename ourselves.
       */
      PRINTF("resolver: Name collision detected for \"%s\".\n", name);

      /* Remove the ".local" suffix. */
      resolv_hostname[strlen(resolv_hostname) - 6] = 0;

      /* Append the last three hex parts of the link-level address. */
      for(i = 0; i < 3; ++i) {
        uint8_t val = uip_lladdr.addr[(UIP_LLADDR_LEN - 3) + i];

        char append_str[4] = "-XX";

        append_str[2] = (((val & 0xF) > 9) ? 'a' : '0') + (val & 0xF);
        val >>= 4;
        append_str[1] = (((val & 0xF) > 9) ? 'a' : '0') + (val & 0xF);
        strncat(resolv_hostname, append_str,
                sizeof(resolv_hostname) - strlen(resolv_hostname));
      }

      /* Re-add the .local suffix */
      strncat(resolv_hostname, ".local", RESOLV_CONF_MAX_DOMAIN_NAME_SIZE);

      start_name_collision_check(CLOCK_SECOND * 5);
    } else if(mdns_state == MDNS_STATE_READY) {
      /* We found a collision after we had already asserted
       * that we owned this name. We need to immediately
       * and explicitly begin probing.
       */
      PRINTF("resolver: Possible name collision, probing...\n");
      start_name_collision_check(0);
    }

  } else
#endif /* RESOLV_CONF_SUPPORTS_MDNS */

#if VERBOSE_DEBUG
  if(ipaddr) {
    PRINTF("resolver: Found address for \"%s\".\n", name);
    PRINTF
      ("resolver: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x \n",
       ((uint8_t *) ipaddr)[0], ((uint8_t *) ipaddr)[1],
       ((uint8_t *) ipaddr)[2], ((uint8_t *) ipaddr)[3],
       ((uint8_t *) ipaddr)[4], ((uint8_t *) ipaddr)[5],
       ((uint8_t *) ipaddr)[6], ((uint8_t *) ipaddr)[7],
       ((uint8_t *) ipaddr)[8], ((uint8_t *) ipaddr)[9],
       ((uint8_t *) ipaddr)[10], ((uint8_t *) ipaddr)[11],
       ((uint8_t *) ipaddr)[12], ((uint8_t *) ipaddr)[13],
       ((uint8_t *) ipaddr)[14], ((uint8_t *) ipaddr)[15]);
  } else {
    PRINTF("resolver: Unable to retrieve address for \"%s\".\n", name);
  }
#endif /* VERBOSE_DEBUG */

  process_post(PROCESS_BROADCAST, resolv_event_found, name);
}
/*---------------------------------------------------------------------------*/
#endif /* UIP_UDP */

/** @} */
/** @} */
