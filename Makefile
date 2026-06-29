# Sentinel — unified real-time machine guardian (GTK4 / C++).
#
# Builds two binaries:
#   sentinel         the unprivileged GTK4 GUI (Vitals + Firewall + Posture)
#   sentinel-daemon  the root backend (firewall via nftables/NFQUEUE +
#                    continuous security-posture scanning)

CXX      = g++
CXXFLAGS = -std=c++17 -Wall -Wextra -O2

GTK_CF   = $(shell pkg-config --cflags gtk4)
GTK_LIB  = $(shell pkg-config --libs gtk4)
GLIB_CF  = $(shell pkg-config --cflags glib-2.0)
GLIB_LIB = $(shell pkg-config --libs glib-2.0)
NFQ_CF   = $(shell pkg-config --cflags libnetfilter_queue libmnl)
NFQ_LIB  = $(shell pkg-config --libs libnetfilter_queue libmnl) -lnetfilter_queue -lnfnetlink

GUI      = sentinel
DAEMON   = sentinel-daemon

# GUI: shell + three pages + the (shared) scan/report engines + tray.
GUI_SRC  = src/main.cpp src/vitals.cpp src/firewall.cpp src/posture.cpp \
           src/scan.cpp src/report.cpp src/tray.cpp
# Daemon: firewall + posture scan engine (no GTK, no report renderer).
DMN_SRC  = src/daemon.cpp src/scan.cpp

PREFIX   = /usr/local
BINDIR   = $(PREFIX)/bin
SBINDIR  = $(PREFIX)/sbin
APPDIR   = /usr/share/applications
ICONDIR  = /usr/share/icons/hicolor/256x256/apps
SVGDIR   = /usr/share/icons/hicolor/scalable/apps
UNITDIR  = /etc/systemd/system
CONFDIR  = /etc/sentinel

# Tools used to rasterize the SVG icon for the 256px PNG (first found wins).
RSVG     = $(shell command -v rsvg-convert 2>/dev/null)
INKSCAPE = $(shell command -v inkscape 2>/dev/null)
CONVERT  = $(shell command -v convert 2>/dev/null)

all: $(GUI) $(DAEMON)

# The GUI links GTK + glib; scan.cpp/report.cpp use glib (GPtrArray, GString).
$(GUI): $(GUI_SRC) src/sentinel.h src/sentinel_proto.h src/scan.hpp src/tray.h
	$(CXX) $(CXXFLAGS) $(GTK_CF) -o $@ $(GUI_SRC) $(GTK_LIB) -lpthread

# The daemon needs nftables/NFQUEUE + glib (scan.cpp), but not GTK.
$(DAEMON): $(DMN_SRC) src/sentinel_proto.h src/scan.hpp src/sha256.h
	$(CXX) $(CXXFLAGS) $(NFQ_CF) $(GLIB_CF) -o $@ $(DMN_SRC) \
	    $(NFQ_LIB) $(GLIB_LIB) -lpthread

clean:
	rm -f $(GUI) $(DAEMON)

icons/sentinel.png: icons/sentinel.svg
	@if [ -n "$(RSVG)" ]; then $(RSVG) -w 256 -h 256 $< -o $@; \
	elif [ -n "$(INKSCAPE)" ]; then $(INKSCAPE) $< -w 256 -h 256 -o $@ >/dev/null 2>&1; \
	elif [ -n "$(CONVERT)" ]; then $(CONVERT) -background none -resize 256x256 $< $@; \
	else echo "  (no rsvg-convert/inkscape/convert — only the SVG icon will be installed)"; fi

install: all icons/sentinel.png
	@echo "Installing binaries..."
	install -d $(DESTDIR)$(BINDIR) $(DESTDIR)$(SBINDIR)
	install -m 0755 $(GUI)    $(DESTDIR)$(BINDIR)/$(GUI)
	install -m 0755 $(DAEMON) $(DESTDIR)$(SBINDIR)/$(DAEMON)

	@echo "Installing desktop entry and icons..."
	install -d $(DESTDIR)$(APPDIR) $(DESTDIR)$(SVGDIR)
	install -m 0644 sentinel.desktop $(DESTDIR)$(APPDIR)/sentinel.desktop
	install -m 0644 icons/sentinel.svg $(DESTDIR)$(SVGDIR)/sentinel.svg
	@if [ -f icons/sentinel.png ]; then \
	    install -d $(DESTDIR)$(ICONDIR); \
	    install -m 0644 icons/sentinel.png $(DESTDIR)$(ICONDIR)/sentinel.png; \
	fi

	@echo "Installing systemd unit..."
	install -d $(DESTDIR)$(UNITDIR)
	install -m 0644 systemd/sentinel-daemon.service $(DESTDIR)$(UNITDIR)/sentinel-daemon.service

	@echo "Installing starter firewall rule store (only if none exists)..."
	install -d $(DESTDIR)$(CONFDIR)
	@if [ ! -f $(DESTDIR)$(CONFDIR)/rules.conf ]; then \
	    install -m 0644 rules.default.conf $(DESTDIR)$(CONFDIR)/rules.conf; \
	    echo "  -> wrote $(CONFDIR)/rules.conf"; \
	else \
	    echo "  -> $(CONFDIR)/rules.conf already present, keeping your rules"; \
	fi

	-gtk-update-icon-cache -f -t /usr/share/icons/hicolor 2>/dev/null || true
	-update-desktop-database $(DESTDIR)$(APPDIR) 2>/dev/null || true

	@# Enable + start the daemon (skipped for staged/DESTDIR builds).
	@if [ -z "$(DESTDIR)" ] && command -v systemctl >/dev/null 2>&1; then \
	    echo "Enabling and starting sentinel-daemon service..."; \
	    systemctl daemon-reload; \
	    systemctl enable --now sentinel-daemon; \
	    echo; \
	    echo "Daemon is running. Launch 'Sentinel' from your menu (or run 'sentinel')."; \
	else \
	    echo; \
	    echo "Installed. Start the daemon with:  systemctl enable --now sentinel-daemon"; \
	fi

uninstall:
	-systemctl disable --now sentinel-daemon 2>/dev/null || true
	rm -f $(DESTDIR)$(BINDIR)/$(GUI)
	rm -f $(DESTDIR)$(SBINDIR)/$(DAEMON)
	rm -f $(DESTDIR)$(APPDIR)/sentinel.desktop
	rm -f $(DESTDIR)$(ICONDIR)/sentinel.png
	rm -f $(DESTDIR)$(SVGDIR)/sentinel.svg
	rm -f $(DESTDIR)$(UNITDIR)/sentinel-daemon.service
	-gtk-update-icon-cache -f -t /usr/share/icons/hicolor 2>/dev/null || true
	-update-desktop-database $(DESTDIR)$(APPDIR) 2>/dev/null || true
	@echo "Uninstalled. (Rule store /etc/sentinel left intact; remove it manually if desired.)"

.PHONY: all clean install uninstall
