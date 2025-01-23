ublksrv_plugin_LTLIBRARIES = tgt_loop.la tgt_null.la
ublksrv_plugindir = $(UBLKSRV_PLUGIN_DIR)

SUBDIRS = nbd

PLUGIN_CPPFLAGS = -I${top_srcdir} -I${top_srcdir}/include -fPIC
PLUGIN_LDFLAGS = -module -avoid-version -ldl -shared

tgt_loop_la_CPPFLAGS = $(PLUGIN_CPPFLAGS)
tgt_loop_la_LDFLAGS = $(PLUGIN_LDFLAGS)
tgt_loop_la_SOURCES = tgt_loop.cpp

tgt_null_la_CPPFLAGS = $(PLUGIN_CPPFLAGS)
tgt_null_la_LDFLAGS = $(PLUGIN_LDFLAGS)
tgt_null_la_SOURCES = tgt_null.cpp
