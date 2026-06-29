// sentinel — unified, real-time machine guardian (GTK4 / C++).
//
// One window that reunites three of the author's tools behind a single
// top-level switcher, each as a self-contained page:
//
//   Vitals    (Pulse)    — live CPU / temperature / memory / disk / network
//   Firewall  (Warden)   — per-process outbound-connection approvals + log
//   Posture   (Envision) — continuous security-posture scan with live change
//                          alerts, served by sentinel-daemon
//
// This file is just the shell: it owns the GtkApplication, the window, the
// app-wide Tokyo Night theme, the system tray, and the About dialog. The pages
// build themselves and run their own timers / socket I/O (see sentinel.h).
//
// Author: Jean-Francois Lachance-Caumartin

#include <gtk/gtk.h>
#ifdef GDK_WINDOWING_X11
#include <gdk/x11/gdkx.h>
#endif

#include "sentinel.h"
#include "sentinel_proto.h"
#include "tray.h"

struct Shell {
    GtkApplication *app   = nullptr;
    GtkWidget      *window = nullptr;
    bool            tray_active = false;
};

// ---------------------------------------------------------------------------
// App-wide theme (the full Tokyo Night palette from Pulse; pages layer their
// own component classes on top at a higher priority).
// ---------------------------------------------------------------------------
static void apply_theme(void) {
    static const char *style =
        "window {"
        "  background-image: radial-gradient(circle at 12% -8%, #2a2f45 0%, #1a1b26 42%),"
        "                    radial-gradient(circle at 110% 120%, #232a47 0%, rgba(26,27,38,0) 55%);"
        "  background-color: #16161e; color: #a9b1d6;"
        "  font-family: 'Inter','Cantarell',sans-serif;"
        "}\n"
        ".page { padding: 16px; }\n"
        ".card {"
        "  background-image: linear-gradient(145deg, rgba(41,46,66,0.96), rgba(31,35,53,0.96));"
        "  border: 1px solid rgba(122,162,247,0.16); border-radius: 14px; padding: 14px 16px;"
        "}\n"
        ".card-blue   { border-left: 3px solid #7aa2f7; }\n"
        ".card-green  { border-left: 3px solid #9ece6a; }\n"
        ".card-red    { border-left: 3px solid #f7768e; }\n"
        ".card-purple { border-left: 3px solid #bb9af7; }\n"
        ".card-cyan   { border-left: 3px solid #7dcfff; }\n"
        ".card-orange { border-left: 3px solid #ff9e64; }\n"
        ".stat-title { font-size: 11px; font-weight: 800; color: #6b74a0; letter-spacing: 1.4px; }\n"
        ".stat-val { font-size: 26px; font-weight: 800; margin-top: 2px;"
        "  text-shadow: 0 0 18px rgba(122,162,247,0.28); }\n"
        ".stat-val-blue   { color: #7aa2f7; }\n"
        ".stat-val-green  { color: #9ece6a; }\n"
        ".stat-val-red    { color: #f7768e; }\n"
        ".stat-val-purple { color: #bb9af7; }\n"
        ".stat-val-cyan   { color: #7dcfff; }\n"
        ".stat-val-orange { color: #ff9e64; }\n"
        ".stat-sub { font-size: 12px; color: #7e85ad; font-weight: 600; margin-top: 2px; }\n"
        ".graph-title { font-size: 12px; font-weight: 800; color: #7aa2f7; letter-spacing: 1.4px; margin-bottom: 6px; }\n"
        ".grid-label-title { font-size: 10px; font-weight: 800; color: #6b74a0; letter-spacing: 1px; }\n"
        ".grid-label-val { font-size: 15px; font-weight: 700; color: #c0caf5; }\n"
        ".panel {"
        "  background-image: linear-gradient(145deg, rgba(41,46,66,0.96), rgba(31,35,53,0.96));"
        "  border: 1px solid rgba(122,162,247,0.16); border-radius: 14px; padding: 14px;"
        "}\n"
        "headerbar {"
        "  background-image: linear-gradient(to bottom, #2a2f45, #1d2030);"
        "  border-bottom: 1px solid rgba(122,162,247,0.25); padding: 6px 10px;"
        "}\n"
        "headerbar .title { font-weight: 800; color: #c0caf5; }\n"
        "stackswitcher button {"
        "  background: none; border: none; box-shadow: none; color: #8a92bd;"
        "  border-radius: 9px; padding: 4px 14px; font-weight: 700; letter-spacing: 0.4px;"
        "}\n"
        "stackswitcher button:hover { background-image: linear-gradient(145deg, rgba(122,162,247,0.18), rgba(122,162,247,0.10)); color: #c0caf5; }\n"
        "stackswitcher button:checked {"
        "  background-image: linear-gradient(145deg, #7aa2f7, #5a7fe0); color: #16161e;"
        "}\n"
        "button {"
        "  background-image: linear-gradient(145deg, #2a2f45, #24283b);"
        "  border: 1px solid rgba(122,162,247,0.28); color: #c0caf5;"
        "  border-radius: 9px; padding: 4px 10px; transition: all 160ms ease;"
        "}\n"
        "button:hover { background-image: linear-gradient(145deg, #7aa2f7, #5a7fe0);"
        "  border-color: #7aa2f7; color: #16161e; }\n"
        "button:disabled { opacity: 0.5; }\n"
        "tooltip { background-color: #1f2335; color: #c0caf5; border: 1px solid #414868; }\n";
    GtkCssProvider *css = gtk_css_provider_new();
    gtk_css_provider_load_from_string(css, style);
    gtk_style_context_add_provider_for_display(
        gdk_display_get_default(), GTK_STYLE_PROVIDER(css),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION);
    g_object_unref(css);
}

// ---------------------------------------------------------------------------
// About
// ---------------------------------------------------------------------------
static void on_about(GtkButton *, gpointer data) {
    Shell *s = (Shell *)data;
    const char *authors[] = { "Jean-Francois Lachance-Caumartin", nullptr };
    gtk_show_about_dialog(GTK_WINDOW(s->window),
        "program-name", "Sentinel",
        "version", SENTINEL_VERSION,
        "logo-icon-name", "sentinel",
        "comments",
            "One window for the whole machine, with real-time checks.\n\n"
            "• Vitals — live CPU, temperature, memory, disk and network (Pulse)\n"
            "• Firewall — approve each program's outbound connections (Warden)\n"
            "• Posture — continuous security-posture scanning with live change\n"
            "  alerts, served by the root sentinel-daemon (Envision)\n\n"
            "Tokyo Night theme · GTK4 · the firewall and posture engines run in\n"
            "sentinel-daemon; the vitals reader needs no privileges.",
        "copyright", "© 2026 Jean-Francois Lachance-Caumartin",
        "license-type", GTK_LICENSE_MIT_X11,
        "authors", authors,
        nullptr);
}

// ---------------------------------------------------------------------------
// System tray — close / minimize to tray, restore from it
// ---------------------------------------------------------------------------
static void raise_front(GtkWidget *window) {
    gtk_window_unminimize(GTK_WINDOW(window));
#ifdef GDK_WINDOWING_X11
    GdkSurface *surf = gtk_native_get_surface(GTK_NATIVE(window));
    if (surf && GDK_IS_X11_SURFACE(surf))
        gdk_x11_surface_set_user_time(surf, gdk_x11_get_server_time(surf));
#endif
    gtk_window_present(GTK_WINDOW(window));
}

static void on_map_raise(GtkWidget *window, gpointer) {
    g_signal_handlers_disconnect_by_func(window, (gpointer)on_map_raise, nullptr);
    raise_front(window);
}

static void present_front(Shell *s) {
    if (!s->window) return;
    if (gtk_widget_get_mapped(s->window)) { raise_front(s->window); return; }
    g_signal_handlers_disconnect_by_func(s->window, (gpointer)on_map_raise, nullptr);
    g_signal_connect(s->window, "map", G_CALLBACK(on_map_raise), nullptr);
    gtk_widget_set_visible(s->window, TRUE);
}

static void tray_show_cb(void *user) { present_front((Shell *)user); }
static void tray_quit_cb(void *user) { g_application_quit(G_APPLICATION(((Shell *)user)->app)); }

static gboolean on_window_close(GtkWindow *win, gpointer data) {
    Shell *s = (Shell *)data;
    if (s->tray_active) { gtk_widget_set_visible(GTK_WIDGET(win), FALSE); return TRUE; }
    return FALSE;
}

static void on_surface_state(GdkToplevel *tl, GParamSpec *, gpointer data) {
    Shell *s = (Shell *)data;
    if (!s->tray_active || !s->window) return;
    if (gdk_toplevel_get_state(tl) & GDK_TOPLEVEL_STATE_MINIMIZED)
        gtk_widget_set_visible(s->window, FALSE);
}

static void on_window_realize(GtkWidget *w, gpointer data) {
    GdkSurface *surf = gtk_native_get_surface(GTK_NATIVE(w));
    if (surf && GDK_IS_TOPLEVEL(surf))
        g_signal_connect(surf, "notify::state", G_CALLBACK(on_surface_state), data);
}

// ---------------------------------------------------------------------------
// Activate
// ---------------------------------------------------------------------------
static void activate(GtkApplication *app, gpointer data) {
    Shell *s = (Shell *)data;
    if (s->window) { present_front(s); return; }
    s->app = app;

    apply_theme();

    s->window = gtk_application_window_new(app);
    gtk_window_set_title(GTK_WINDOW(s->window), "Sentinel");
    gtk_window_set_default_size(GTK_WINDOW(s->window), 1180, 700);
    gtk_window_set_icon_name(GTK_WINDOW(s->window), "sentinel");

    // Top-level stack: the three reunited tools.
    GtkWidget *stack = gtk_stack_new();
    gtk_stack_set_transition_type(GTK_STACK(stack), GTK_STACK_TRANSITION_TYPE_CROSSFADE);
    gtk_stack_add_titled(GTK_STACK(stack), vitals_build(GTK_WINDOW(s->window)),   "vitals",   "Vitals");
    gtk_stack_add_titled(GTK_STACK(stack), firewall_build(GTK_WINDOW(s->window)), "firewall", "Firewall");
    gtk_stack_add_titled(GTK_STACK(stack), posture_build(GTK_WINDOW(s->window)),  "posture",  "Posture");
    gtk_widget_set_vexpand(stack, TRUE);

    // Header bar with the top-level switcher + About.
    GtkWidget *header = gtk_header_bar_new();
    gtk_header_bar_set_show_title_buttons(GTK_HEADER_BAR(header), TRUE);
    GtkWidget *switcher = gtk_stack_switcher_new();
    gtk_stack_switcher_set_stack(GTK_STACK_SWITCHER(switcher), GTK_STACK(stack));
    gtk_header_bar_set_title_widget(GTK_HEADER_BAR(header), switcher);
    gtk_window_set_titlebar(GTK_WINDOW(s->window), header);

    GtkWidget *about_btn = gtk_button_new_from_icon_name("help-about-symbolic");
    gtk_widget_set_tooltip_text(about_btn, "About Sentinel");
    g_signal_connect(about_btn, "clicked", G_CALLBACK(on_about), s);
    gtk_header_bar_pack_end(GTK_HEADER_BAR(header), about_btn);

    gtk_window_set_child(GTK_WINDOW(s->window), stack);

    // Offer a tray icon: closing/minimizing then hides to the tray (so the
    // firewall page keeps answering prompts and the posture feed keeps running).
    s->tray_active = tray_init(G_APPLICATION(app), "sentinel",
                               tray_show_cb, tray_quit_cb, s);
    g_signal_connect(s->window, "close-request", G_CALLBACK(on_window_close), s);
    g_signal_connect(s->window, "realize", G_CALLBACK(on_window_realize), s);

    present_front(s);
}

int main(int argc, char **argv) {
    Shell shell;
    shell.app = gtk_application_new("org.jflc.sentinel", G_APPLICATION_DEFAULT_FLAGS);
    g_signal_connect(shell.app, "activate", G_CALLBACK(activate), &shell);
    int status = g_application_run(G_APPLICATION(shell.app), argc, argv);
    g_object_unref(shell.app);
    return status;
}
