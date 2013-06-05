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
static const char* name1 = "light3._llight";
static const char *txt1 = "\005if=01";
static const char *ptr1 = "";
static const char *common_suffix1 = "_coap._udp.local";

static const char* name2 = "temp1";
static const char *txt2 = "\005if=02";
static const char *ptr2 = "";
static const char *common_suffix2 = "_coap._udp.local";

//static const char *query="light1._light._coap._udp.local";
static const char *query="_coap._udp.local";
//static const char *query="temp1._temp._coap._udp.local";
PROCESS_THREAD(mdns_process, ev, data)
{
  static struct etimer et;
  PROCESS_BEGIN();
  uint16_t port = 1234;
  uint16_t priority = 1;
  uint16_t weight = 0;

  int i;
  uip_ipaddr_t* local_address;
  for (i = 0; i < UIP_DS6_ADDR_NB; i++){
      if (uip_ds6_if.addr_list[i].isused)
        local_address = &uip_ds6_if.addr_list[i].ipaddr;
  }
  resolv_add_service(name1, port, priority, weight, txt1, ptr1, 1, common_suffix1, local_address);
  resolv_add_service(name2, port, priority, weight, txt2, ptr2, 1, common_suffix2, local_address);
  resolv_query(query);

  PROCESS_END();
}
