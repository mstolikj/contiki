/*
 * This is an example application to test the functionality of the mDNS/DNS-SD resolver.
 *
 * \author Richard P.H.F.M Verhoeven <P.H.F.M.Verhoeven@tue.nl>
 * \author Milosh Stolikj <m.stolikj@tue.nl>
 * */
#define DEBUG DEBUG_PRINT
#include "net/uip-debug.h"
#include "net/resolv.h"
#include "net/uip-ds6.h"
/*---------------------------------------------------------------------------*/
PROCESS(mdns_process, "mDNS test");
AUTOSTART_PROCESSES(&resolv_process, &mdns_process);
/*---------------------------------------------------------------------------*/

DNS_STATIC_SERVICE(light, "light3._llight", 1234, "\005if=01",
		   "", "_coap._udp.local");

DNS_STATIC_SERVICE(temp, "temp1", 1234, "\005if=02", "", "_coap._udp.local");

static const char *query="_coap._udp.local";
PROCESS_THREAD(mdns_process, ev, data)
{
  static struct etimer et;
  PROCESS_BEGIN();
  static struct service_resolv_entry_t* resolved_service;

  int i;
  uip_ipaddr_t* local_address;
  for (i = 0; i < UIP_DS6_ADDR_NB; i++){
      if (uip_ds6_if.addr_list[i].isused)
        local_address = &uip_ds6_if.addr_list[i].ipaddr;
  }
  resolv_add_service(DNS_SERVICE(light), local_address);
  resolv_add_service(DNS_SERVICE(temp), local_address);
  resolv_query(query);

  static resolv_status_t status = RESOLV_STATUS_ERROR;
  etimer_set(&et, 1);
  while(status != RESOLV_STATUS_CACHED) {
      PROCESS_YIELD();
      etimer_restart(&et);
      status = resolv_lookup_service(query,&resolved_service);
  }
  PRINTF("%s\n", resolved_service->queryname);
  PRINTF("%s:%d: %s\n", resolved_service->servicename, resolved_service->port, resolved_service->txt);
  PRINTF("%s->", resolved_service->hostname);
  PRINT6ADDR(resolved_service->ipaddr);
  PRINTF("\n");

  PROCESS_END();
}
