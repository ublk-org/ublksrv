ublksrv_plugin_LTLIBRARIES = tgt_nbd.la
ublksrv_plugindir = $(UBLKSRV_PLUGIN_DIR)

PLUGIN_CPPFLAGS = -I${top_srcdir} -I${top_srcdir}/include -fPIC
PLUGIN_LDFLAGS = -module -avoid-version -ldl -shared

tgt_nbd_la_CPPFLAGS = $(PLUGIN_CPPFLAGS)
tgt_nbd_la_LDFLAGS = $(PLUGIN_LDFLAGS)
tgt_nbd_la_SOURCES = tgt_nbd.cpp cliserv.c nbd-client.c

