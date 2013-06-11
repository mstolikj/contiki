all: udp-server udp-client

UIP_CONF_IPV6=1
#SMALL=1
CFLAGS += -DRESOLV_CONF_SUPPORTS_MDNS=1
CFLAGS += -DRESOLV_CONF_SUPPORTS_DNS_SD=1
CFLAGS += -DPROJECT_CONF_H=\"project-conf.h\"
CONTIKI = ../..
include $(CONTIKI)/Makefile.include
