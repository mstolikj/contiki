all: mdns

CONTIKI=../../..

WITH_UIP6=1
UIP_CONF_IPV6=1
#UIP_CONF_RPL=1
#CFLAGS+= -DUIP_CONF_IPV6_RPL
CFLAGS+=-DUIP_CONF_IPV6
SMALL=1
#APPS += webserver
CFLAGS += -ffunction-sections
LDFLAGS += -Wl,--gc-sections,--undefined=_reset_vector__,--undefined=InterruptVectors,--undefined=_copy_data_init__,--undefined=_clear_bss_init__,--undefined=_end_of_init__

CFLAGS += -DPROJECT_CONF_H=\"project-conf.h\"
#DEFINES=NETSTACK_CONF_RDC=nullrdc_driver,NETSTACK_CONF_RDC_CHANNEL_CHECK_RATE=16,NETSTACK_CONF_MAC=nullmac_driver
#CONTIKI_SOURCEFILES += wget.c
#PROJECTDIRS += ../rpl-border-router
#PROJECT_SOURCEFILES += httpd-simple.c

include $(CONTIKI)/Makefile.include

#$(CONTIKI)/tools/tunslip6:	$(CONTIKI)/tools/tunslip6.c
#	(cd $(CONTIKI)/tools && $(MAKE) tunslip6)

#connect-router:	$(CONTIKI)/tools/tunslip6
#	sudo $(CONTIKI)/tools/tunslip6 aaaa::1/64

#connect-router-cooja:	$(CONTIKI)/tools/tunslip6
#	sudo $(CONTIKI)/tools/tunslip6 -a 127.0.0.1 aaaa::1/64
