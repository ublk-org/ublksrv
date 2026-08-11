XSLTPROC = /usr/bin/xsltproc

# Manpages
#
# ublk.1 is generated from ublk.1.xml, but is kept in the tree and shipped in
# the tarball: automake does not distribute plain man_MANS, so without dist_
# the manpage is missing from the release and 'make distcheck' fails with
# "No rule to make target 'ublk.1'".
dist_man1_MANS = ublk.1

%.1 : %.1.xml
	-test -z "$(XSLTPROC)" || $(XSLTPROC) -o $@ http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<
