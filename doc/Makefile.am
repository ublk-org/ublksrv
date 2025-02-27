XSLTPROC = /usr/bin/xsltproc

# Manpages
man1_MANS = ublk.1

%.1 : %.1.xml
	-test -z "$(XSLTPROC)" || $(XSLTPROC) -o $@ http://docbook.sourceforge.net/release/xsl/current/manpages/docbook.xsl $<
