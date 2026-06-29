// sentinel.h — internal contract between the unified GUI's page modules and the
// application shell (main.cpp).
//
// Sentinel is one window with a top-level GtkStack of three pages, each built by
// its own translation unit:
//   * vitals.cpp   — live system vitals (ported from Pulse), unprivileged
//   * firewall.cpp — per-process outbound firewall (ported from Warden)
//   * posture.cpp  — live security posture (ported from Envision)
//
// The firewall and posture pages both talk to sentinel-daemon over one shared
// Unix-socket connection owned by firewall.cpp; posture frames received there are
// handed to posture.cpp through posture_on_line().
//
// Author: Jean-Francois Lachance-Caumartin
#pragma once
#include <gtk/gtk.h>

// Each page returns its root widget. `parent` is the top-level window, used for
// transient dialogs (file choosers, prompts). Builders also start their own
// timers / socket I/O as needed.
GtkWidget *vitals_build  (GtkWindow *parent);
GtkWidget *firewall_build(GtkWindow *parent);
GtkWidget *posture_build (GtkWindow *parent);

// firewall.cpp owns the daemon socket. It forwards any line beginning with a
// posture opcode (PBEGIN/PFINDING/PEND/PALERT) to this handler in posture.cpp.
void posture_on_line(const char *line);

// posture.cpp asks firewall.cpp to send a control line to the daemon (e.g.
// "SCANNOW") over the shared socket. Returns false if not connected.
bool daemon_send(const char *line);
