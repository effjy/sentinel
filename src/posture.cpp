// posture.cpp — Sentinel's live security-posture page (ported from Envision and
// turned real-time).
//
// Unlike Envision's one-shot scan, this page is *fed* by sentinel-daemon, which
// re-runs the full posture scan on an interval. Each scan arrives as a framed
// snapshot (PBEGIN .. PFINDING* .. PEND) that rebuilds the findings list, and
// the daemon also pushes PALERT lines for anything that changed since the last
// scan — those stream into a live "Changes" feed so a newly-opened port or a
// failed service shows up the moment it happens.
//
// firewall.cpp owns the daemon socket and forwards posture lines here via
// posture_on_line(); the "Scan now" button asks for an immediate scan through
// daemon_send("SCANNOW").
//
// Author: Jean-Francois Lachance-Caumartin

#include <gtk/gtk.h>
#include <sys/utsname.h>

#include <cstdio>
#include <string>
#include <vector>

#include "sentinel.h"
#include "sentinel_proto.h"
#include "scan.hpp"

// A finding as received over the wire.
struct PF { int sev; std::string cat, title, detail, suggest, fix; };

// ---------------------------------------------------------------------------
// Page state (one instance)
// ---------------------------------------------------------------------------
struct Post {
    GtkWidget *window      = nullptr;   // top-level, for dialogs
    GtkWidget *count_lbl[5]= {nullptr,nullptr,nullptr,nullptr,nullptr};
    GtkWidget *scanned_lbl = nullptr;
    GtkWidget *findings_box= nullptr;   // GtkListBox of expanders
    GtkWidget *changes_box = nullptr;   // GtkListBox of change alerts
    GtkWidget *pdf_btn     = nullptr;
    GtkWidget *txt_btn     = nullptr;

    std::vector<PF> cur;                // committed findings (last full snapshot)
    std::vector<PF> building;           // accumulated between PBEGIN and PEND
    int counts[5] = {0,0,0,0,0};
    std::string scanned_at;
    bool changes_seen = false;
};

static Post g_po;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
static std::vector<std::string> split_tabs(const char *s) {
    std::vector<std::string> out; std::string cur;
    for (const char *p = s; *p; ++p) { if (*p == '\t') { out.push_back(cur); cur.clear(); } else cur += *p; }
    out.push_back(cur);
    return out;
}

// Colour-marked "[SEV]" tag using Envision's per-severity colours.
static std::string sev_markup(int sev) {
    const char *name = severity_name((Severity)sev);
    const char *col  = severity_color((Severity)sev);
    char *esc = g_markup_escape_text(name, -1);
    std::string m = std::string("<span foreground='") + col + "' weight='bold'>" + esc + "</span>";
    g_free(esc);
    return m;
}

// ---------------------------------------------------------------------------
// Findings list — one expander per finding, most severe first
// ---------------------------------------------------------------------------
static void clear_box(GtkWidget *box) {
    GtkWidget *c;
    while ((c = gtk_widget_get_first_child(box)))
        gtk_list_box_remove(GTK_LIST_BOX(box), c);
}

static GtkWidget *detail_label(const char *prefix, const std::string &body, bool mono) {
    GtkWidget *l = gtk_label_new(nullptr);
    char *esc = g_markup_escape_text(body.c_str(), -1);
    std::string m = std::string("<b>") + prefix + "</b> ";
    if (mono) m += std::string("<tt>") + esc + "</tt>"; else m += esc;
    gtk_label_set_markup(GTK_LABEL(l), m.c_str());
    g_free(esc);
    gtk_label_set_xalign(GTK_LABEL(l), 0.0);
    gtk_label_set_wrap(GTK_LABEL(l), TRUE);
    gtk_label_set_selectable(GTK_LABEL(l), TRUE);
    gtk_widget_set_margin_start(l, 12);
    return l;
}

static void rebuild_findings(Post *p) {
    clear_box(p->findings_box);
    if (p->cur.empty()) {
        GtkWidget *row = gtk_label_new("Waiting for the first posture scan…");
        gtk_widget_add_css_class(row, "p-dim");
        gtk_list_box_append(GTK_LIST_BOX(p->findings_box), row);
        return;
    }
    for (int sev = SEV_CRITICAL; sev >= SEV_OK; sev--) {
        for (const PF &f : p->cur) {
            if (f.sev != sev) continue;
            char *cat = g_markup_escape_text(f.cat.c_str(), -1);
            char *ttl = g_markup_escape_text(f.title.c_str(), -1);
            std::string lbl = "[" + sev_markup(sev) + "]  <b>" + ttl +
                              "</b>  <span foreground='#565f89'>" + cat + "</span>";
            g_free(cat); g_free(ttl);

            GtkWidget *header = gtk_label_new(nullptr);
            gtk_label_set_markup(GTK_LABEL(header), lbl.c_str());
            gtk_label_set_xalign(GTK_LABEL(header), 0.0);
            gtk_label_set_wrap(GTK_LABEL(header), TRUE);

            GtkWidget *exp = gtk_expander_new(nullptr);
            gtk_expander_set_label_widget(GTK_EXPANDER(exp), header);

            GtkWidget *body = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
            gtk_widget_set_margin_top(body, 4); gtk_widget_set_margin_bottom(body, 8);
            if (!f.detail.empty())
                gtk_box_append(GTK_BOX(body), detail_label("Observed:", f.detail, false));
            if (!f.suggest.empty())
                gtk_box_append(GTK_BOX(body), detail_label("Advice:", f.suggest, false));
            if (!f.fix.empty())
                gtk_box_append(GTK_BOX(body), detail_label("Fix:", f.fix, true));
            gtk_expander_set_child(GTK_EXPANDER(exp), body);

            gtk_widget_set_margin_top(exp, 2); gtk_widget_set_margin_bottom(exp, 2);
            gtk_widget_set_margin_start(exp, 6); gtk_widget_set_margin_end(exp, 6);
            gtk_list_box_append(GTK_LIST_BOX(p->findings_box), exp);
        }
    }
}

static void update_summary(Post *p) {
    static const char *names[5] = {"OK","LOW","MEDIUM","HIGH","CRITICAL"};
    for (int i = 0; i < 5; i++) {
        char buf[160];
        snprintf(buf, sizeof(buf),
                 "<span foreground='%s' weight='bold' size='x-large'>%d</span>\n"
                 "<span foreground='#6b74a0' size='small'>%s</span>",
                 severity_color((Severity)i), p->counts[i], names[i]);
        gtk_label_set_markup(GTK_LABEL(p->count_lbl[i]), buf);
    }
    std::string when = "Last scan: " + (p->scanned_at.empty() ? std::string("—") : p->scanned_at);
    gtk_label_set_text(GTK_LABEL(p->scanned_lbl), when.c_str());
}

// ---------------------------------------------------------------------------
// Live "Changes" feed (PALERT)
// ---------------------------------------------------------------------------
static void changes_add(Post *p, int sev, const std::string &cat, const std::string &title) {
    if (!p->changes_seen) {        // drop the placeholder on first real alert
        clear_box(p->changes_box);
        p->changes_seen = true;
    }
    char ts[16];
    { time_t now = time(nullptr); struct tm tm; localtime_r(&now, &tm);
      strftime(ts, sizeof(ts), "%H:%M:%S", &tm); }

    char *cat_e = g_markup_escape_text(cat.c_str(), -1);
    char *ttl_e = g_markup_escape_text(title.c_str(), -1);
    std::string m;
    if (sev == SEV_OK) {           // a previously-bad finding cleared
        m = std::string("<span foreground='#565f89'>") + ts + "</span>  "
            "<span foreground='#9ece6a' weight='bold'>✓ cleared</span>  "
            "<b>" + ttl_e + "</b>  <span foreground='#565f89'>" + cat_e + "</span>";
    } else {                       // a new or worsened problem
        m = std::string("<span foreground='#565f89'>") + ts + "</span>  "
            "<span foreground='" + severity_color((Severity)sev) + "' weight='bold'>⚠ " +
            severity_name((Severity)sev) + "</span>  "
            "<b>" + ttl_e + "</b>  <span foreground='#565f89'>" + cat_e + "</span>";
    }
    g_free(cat_e); g_free(ttl_e);

    GtkWidget *row = gtk_label_new(nullptr);
    gtk_label_set_markup(GTK_LABEL(row), m.c_str());
    gtk_label_set_xalign(GTK_LABEL(row), 0.0);
    gtk_label_set_wrap(GTK_LABEL(row), TRUE);
    gtk_widget_set_margin_top(row, 3); gtk_widget_set_margin_bottom(row, 3);
    gtk_widget_set_margin_start(row, 8); gtk_widget_set_margin_end(row, 8);
    gtk_list_box_insert(GTK_LIST_BOX(p->changes_box), row, 0);   // newest on top
}

// ---------------------------------------------------------------------------
// Wire handler — called by firewall.cpp for every posture line
// ---------------------------------------------------------------------------
void posture_on_line(const char *line) {
    Post *p = &g_po;
    if (!p->findings_box) return;   // page not built yet

    if (strncmp(line, "PBEGIN\t", 7) == 0) {
        auto f = split_tabs(line + 7);   // scanned_at_b64, c0..c4
        p->building.clear();
        if (f.size() >= 6) {
            p->scanned_at = sentinel_b64::decode(f[0]);
            for (int i = 0; i < 5; i++) p->counts[i] = atoi(f[1 + i].c_str());
        }
    } else if (strncmp(line, "PFINDING\t", 9) == 0) {
        auto f = split_tabs(line + 9);   // sev, cat, title, detail, suggest, fix (b64)
        if (f.size() >= 6) {
            PF x;
            x.sev     = atoi(f[0].c_str());
            x.cat     = sentinel_b64::decode(f[1]);
            x.title   = sentinel_b64::decode(f[2]);
            x.detail  = sentinel_b64::decode(f[3]);
            x.suggest = sentinel_b64::decode(f[4]);
            x.fix     = sentinel_b64::decode(f[5]);
            p->building.push_back(std::move(x));
        }
    } else if (strcmp(line, "PEND") == 0) {
        p->cur = std::move(p->building);
        p->building.clear();
        rebuild_findings(p);
        update_summary(p);
        gtk_widget_set_sensitive(p->pdf_btn, TRUE);
        gtk_widget_set_sensitive(p->txt_btn, TRUE);
    } else if (strncmp(line, "PALERT\t", 7) == 0) {
        auto f = split_tabs(line + 7);   // sev, cat_b64, title_b64
        if (f.size() >= 3)
            changes_add(p, atoi(f[0].c_str()),
                        sentinel_b64::decode(f[1]), sentinel_b64::decode(f[2]));
    }
}

// ---------------------------------------------------------------------------
// Export — reconstruct a ScanReport from the live findings and reuse report.cpp
// ---------------------------------------------------------------------------
static ScanReport *make_report(Post *p, std::vector<Finding> &storage) {
    storage.clear();
    storage.reserve(p->cur.size());
    GPtrArray *items = g_ptr_array_new();     // no free func: points into `storage`
    for (PF &f : p->cur) {
        Finding fd;
        fd.category    = const_cast<char *>(f.cat.c_str());
        fd.title       = const_cast<char *>(f.title.c_str());
        fd.severity    = (Severity)f.sev;
        fd.detail      = const_cast<char *>(f.detail.c_str());
        fd.suggestion  = const_cast<char *>(f.suggest.c_str());
        fd.fix_command = f.fix.empty() ? nullptr : const_cast<char *>(f.fix.c_str());
        storage.push_back(fd);
    }
    for (Finding &fd : storage) g_ptr_array_add(items, &fd);

    ScanReport *r = g_new0(ScanReport, 1);
    r->items = items;
    for (int i = 0; i < 5; i++) r->counts[i] = p->counts[i];
    r->hostname   = g_strdup(g_get_host_name());
    struct utsname un; r->kernel = g_strdup(uname(&un) == 0 ? un.release : "");
    char *os = nullptr; gsize len = 0;
    if (g_file_get_contents("/etc/os-release", &os, &len, nullptr) && os) {
        char *pp = strstr(os, "PRETTY_NAME=");
        std::string pretty;
        if (pp) { pp += 12; if (*pp=='"') pp++; while (*pp && *pp!='"' && *pp!='\n') pretty += *pp++; }
        r->os_pretty = g_strdup(pretty.c_str());
        g_free(os);
    } else r->os_pretty = g_strdup("");
    r->scanned_at = g_strdup(p->scanned_at.c_str());
    r->is_root = TRUE;            // the daemon scans as root
    return r;
}

static void free_report(ScanReport *r) {
    g_ptr_array_free(r->items, FALSE);   // we owned the array but not the findings
    g_free(r->hostname); g_free(r->os_pretty); g_free(r->kernel); g_free(r->scanned_at);
    g_free(r);
}

static void show_msg(Post *p, const char *m) {
    GtkAlertDialog *d = gtk_alert_dialog_new("%s", m);
    gtk_alert_dialog_show(d, p->window ? GTK_WINDOW(p->window) : nullptr);
    g_object_unref(d);
}

static void on_save_pdf_ready(GObject *src, GAsyncResult *res, gpointer data) {
    Post *p = (Post *)data;
    GError *err = nullptr;
    GFile *f = gtk_file_dialog_save_finish(GTK_FILE_DIALOG(src), res, &err);
    if (!f) { if (err) g_error_free(err); return; }
    char *path = g_file_get_path(f); g_object_unref(f);
    if (!path) return;
    if (!g_str_has_suffix(path, ".pdf")) { char *q = g_strconcat(path, ".pdf", nullptr); g_free(path); path = q; }

    std::vector<Finding> storage;
    ScanReport *r = make_report(p, storage);
    char *tex = report_to_latex(r);
    char *werr = nullptr;
    gboolean ok = report_write_pdf(tex, path, &werr);
    g_free(tex); free_report(r);
    if (ok) { char *m = g_strdup_printf("PDF saved to:\n%s", path); show_msg(p, m); g_free(m); }
    else    { char *m = g_strdup_printf("Could not create PDF.\n%s", werr ? werr : "Unknown error"); show_msg(p, m); g_free(m); }
    g_free(werr); g_free(path);
}

static void on_save_txt_ready(GObject *src, GAsyncResult *res, gpointer data) {
    Post *p = (Post *)data;
    GError *err = nullptr;
    GFile *f = gtk_file_dialog_save_finish(GTK_FILE_DIALOG(src), res, &err);
    if (!f) { if (err) g_error_free(err); return; }
    char *path = g_file_get_path(f); g_object_unref(f);
    if (!path) return;

    std::vector<Finding> storage;
    ScanReport *r = make_report(p, storage);
    char *txt = report_to_text(r);
    GError *werr = nullptr;
    if (!g_file_set_contents(path, txt, -1, &werr)) {
        show_msg(p, werr ? werr->message : "write failed");
        if (werr) g_error_free(werr);
    }
    g_free(txt); free_report(r); g_free(path);
}

static GtkFileDialog *save_dialog(const char *title, const char *name) {
    GtkFileDialog *d = gtk_file_dialog_new();
    gtk_file_dialog_set_title(d, title);
    gtk_file_dialog_set_initial_name(d, name);
    GFile *folder = g_file_new_for_path(g_get_home_dir());
    gtk_file_dialog_set_initial_folder(d, folder);
    g_object_unref(folder);
    return d;
}

static void on_pdf_clicked(GtkButton *, gpointer data) {
    Post *p = (Post *)data;
    if (p->cur.empty()) return;
    GtkFileDialog *d = save_dialog("Save posture report as PDF", "sentinel-posture.pdf");
    gtk_file_dialog_save(d, p->window ? GTK_WINDOW(p->window) : nullptr, nullptr, on_save_pdf_ready, p);
    g_object_unref(d);
}

static void on_txt_clicked(GtkButton *, gpointer data) {
    Post *p = (Post *)data;
    if (p->cur.empty()) return;
    GtkFileDialog *d = save_dialog("Save posture report as text", "sentinel-posture.txt");
    gtk_file_dialog_save(d, p->window ? GTK_WINDOW(p->window) : nullptr, nullptr, on_save_txt_ready, p);
    g_object_unref(d);
}

static void on_scan_now(GtkButton *, gpointer) {
    if (!daemon_send("SCANNOW")) { /* not connected yet; the daemon scans on its own timer anyway */ }
}

// ---------------------------------------------------------------------------
// Page-specific CSS
// ---------------------------------------------------------------------------
static void apply_posture_css(void) {
    static const char *CSS =
        ".p-dim { color: #565f89; }"
        ".p-title { font-weight: bold; font-size: 16px; color: #7aa2f7; }"
        ".sevcard { background-color: #16161e; border: 1px solid rgba(122,162,247,0.16);"
        "  border-radius: 12px; padding: 8px 18px; }"
        "expander > title { padding: 4px; }"
        "list, row { background-color: transparent; }";
    GtkCssProvider *p = gtk_css_provider_new();
    gtk_css_provider_load_from_string(p, CSS);
    gtk_style_context_add_provider_for_display(
        gdk_display_get_default(), GTK_STYLE_PROVIDER(p),
        GTK_STYLE_PROVIDER_PRIORITY_APPLICATION + 1);
    g_object_unref(p);
}

// ---------------------------------------------------------------------------
// Page entry point
// ---------------------------------------------------------------------------
GtkWidget *posture_build(GtkWindow *parent) {
    Post *p = &g_po;
    p->window = GTK_WIDGET(parent);
    apply_posture_css();

    GtkWidget *root = gtk_box_new(GTK_ORIENTATION_VERTICAL, 8);
    gtk_widget_set_margin_top(root, 10); gtk_widget_set_margin_bottom(root, 10);
    gtk_widget_set_margin_start(root, 14); gtk_widget_set_margin_end(root, 14);

    // Header: title + scanned-at + actions
    GtkWidget *header = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    GtkWidget *titlebox = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    GtkWidget *title = gtk_label_new("SECURITY POSTURE");
    gtk_label_set_xalign(GTK_LABEL(title), 0.0);
    gtk_widget_add_css_class(title, "p-title");
    p->scanned_lbl = gtk_label_new("Last scan: —");
    gtk_label_set_xalign(GTK_LABEL(p->scanned_lbl), 0.0);
    gtk_widget_add_css_class(p->scanned_lbl, "p-dim");
    gtk_box_append(GTK_BOX(titlebox), title);
    gtk_box_append(GTK_BOX(titlebox), p->scanned_lbl);
    gtk_widget_set_hexpand(titlebox, TRUE);
    gtk_box_append(GTK_BOX(header), titlebox);

    GtkWidget *scan_btn = gtk_button_new_with_label("Scan now");
    g_signal_connect(scan_btn, "clicked", G_CALLBACK(on_scan_now), p);
    gtk_widget_set_valign(scan_btn, GTK_ALIGN_CENTER);
    p->pdf_btn = gtk_button_new_with_label("Save PDF");
    gtk_widget_set_sensitive(p->pdf_btn, FALSE);
    g_signal_connect(p->pdf_btn, "clicked", G_CALLBACK(on_pdf_clicked), p);
    gtk_widget_set_valign(p->pdf_btn, GTK_ALIGN_CENTER);
    p->txt_btn = gtk_button_new_with_label("Save text");
    gtk_widget_set_sensitive(p->txt_btn, FALSE);
    g_signal_connect(p->txt_btn, "clicked", G_CALLBACK(on_txt_clicked), p);
    gtk_widget_set_valign(p->txt_btn, GTK_ALIGN_CENTER);
    gtk_box_append(GTK_BOX(header), scan_btn);
    gtk_box_append(GTK_BOX(header), p->pdf_btn);
    gtk_box_append(GTK_BOX(header), p->txt_btn);
    gtk_box_append(GTK_BOX(root), header);

    // Severity summary cards
    GtkWidget *cards = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_box_set_homogeneous(GTK_BOX(cards), TRUE);
    for (int i = SEV_CRITICAL; i >= SEV_OK; i--) {
        p->count_lbl[i] = gtk_label_new(nullptr);
        gtk_widget_add_css_class(p->count_lbl[i], "sevcard");
        gtk_widget_set_hexpand(p->count_lbl[i], TRUE);
        gtk_box_append(GTK_BOX(cards), p->count_lbl[i]);
    }
    gtk_box_append(GTK_BOX(root), cards);

    // Two-pane body: findings (left, wide) and live changes feed (right).
    GtkWidget *panes = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_widget_set_vexpand(panes, TRUE);

    GtkWidget *fwrap = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_widget_set_hexpand(fwrap, TRUE);
    GtkWidget *flab = gtk_label_new("Findings");
    gtk_label_set_xalign(GTK_LABEL(flab), 0.0);
    gtk_widget_add_css_class(flab, "p-dim");
    p->findings_box = gtk_list_box_new();
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(p->findings_box), GTK_SELECTION_NONE);
    GtkWidget *fscroll = gtk_scrolled_window_new();
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(fscroll), p->findings_box);
    gtk_widget_set_vexpand(fscroll, TRUE);
    gtk_box_append(GTK_BOX(fwrap), flab);
    gtk_box_append(GTK_BOX(fwrap), fscroll);

    GtkWidget *cwrap = gtk_box_new(GTK_ORIENTATION_VERTICAL, 4);
    gtk_widget_set_size_request(cwrap, 320, -1);
    GtkWidget *clab = gtk_label_new("Changes (live)");
    gtk_label_set_xalign(GTK_LABEL(clab), 0.0);
    gtk_widget_add_css_class(clab, "p-dim");
    p->changes_box = gtk_list_box_new();
    gtk_list_box_set_selection_mode(GTK_LIST_BOX(p->changes_box), GTK_SELECTION_NONE);
    GtkWidget *placeholder = gtk_label_new("No changes yet — this feed lights up\nwhen your posture changes.");
    gtk_widget_add_css_class(placeholder, "p-dim");
    gtk_list_box_append(GTK_LIST_BOX(p->changes_box), placeholder);
    GtkWidget *cscroll = gtk_scrolled_window_new();
    gtk_scrolled_window_set_child(GTK_SCROLLED_WINDOW(cscroll), p->changes_box);
    gtk_widget_set_vexpand(cscroll, TRUE);
    gtk_box_append(GTK_BOX(cwrap), clab);
    gtk_box_append(GTK_BOX(cwrap), cscroll);

    gtk_box_append(GTK_BOX(panes), fwrap);
    gtk_box_append(GTK_BOX(panes), cwrap);
    gtk_box_append(GTK_BOX(root), panes);

    update_summary(p);
    rebuild_findings(p);
    return root;
}
