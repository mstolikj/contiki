all: mdns

CONTIKI=../../..

WITH_UIP6=1
UIP_CONF_IPV6=1
CFLAGS+=-DUIP_CONF_IPV6
SMALL=1
CFLAGS += -ffunction-sections
LDFLAGS += -Wl,--gc-sections,--undefined=_reset_vector__,--undefined=InterruptVectors,--undefined=_copy_data_init__,--undefined=_clear_bss_init__,--undefined=_end_of_init__

CFLAGS += -DPROJECT_CONF_H=\"project-conf.h\"

include $(CONTIKI)/Makefile.include
