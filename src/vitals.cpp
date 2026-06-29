// Pulse — unified system-vitals monitor (GTK4 / C++)
//
// One window that assembles real-time monitoring of the whole machine:
// CPU load & per-core usage, CPU temperature (°C / °F), load averages and
// frequency, RAM & swap, per-filesystem disk usage with live I/O throughput,
// and network up/down speed with live connection counts.
//
// Tokyo Night ("Aurora") theme, Cairo graphs. Built to fit a 1366×768 screen,
// laid out horizontally with tabs (a GtkStack switcher) across the top.
//
// Author: Jean-Francois Lachance-Caumartin
// Assembles and extends the author's diskmon, usage, connmon and ram tools.

#include <gtk/gtk.h>
#ifdef GDK_WINDOWING_X11
#include <gdk/x11/gdkx.h>   // gdk_x11_get_server_time / set_user_time (raise-to-front)
#endif

#include "sentinel.h"

#include <sys/statvfs.h>

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <dirent.h>
#include <fstream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

#define PULSE_VERSION "1.0.0"

static const int HISTORY_MAX = 60;  // points kept in each graph

// ---------------------------------------------------------------------------
// Tokyo Night palette (r,g,b in 0..1)
// ---------------------------------------------------------------------------
struct RGB { double r, g, b; };
static const RGB COL_BLUE   = {0.478, 0.635, 0.968};  // #7aa2f7
static const RGB COL_GREEN  = {0.619, 0.807, 0.415};  // #9ece6a
static const RGB COL_RED    = {0.968, 0.462, 0.556};  // #f7768e
static const RGB COL_PURPLE = {0.733, 0.604, 0.968};  // #bb9af7
static const RGB COL_CYAN   = {0.490, 0.812, 1.000};  // #7dcfff
static const RGB COL_ORANGE = {1.000, 0.619, 0.392};  // #ff9e64

// ---------------------------------------------------------------------------
// Formatting helpers
// ---------------------------------------------------------------------------
static std::string fmt_speed(double bps) {
    const char *u[] = {"B/s", "KB/s", "MB/s", "GB/s", "TB/s"};
    int i = 0;
    while (bps >= 1024.0 && i < 4) { bps /= 1024.0; i++; }
    char b[48]; snprintf(b, sizeof(b), "%.1f %s", bps, u[i]);
    return b;
}
static std::string fmt_bytes(double v) {
    const char *u[] = {"B", "KB", "MB", "GB", "TB"};
    int i = 0;
    while (v >= 1024.0 && i < 4) { v /= 1024.0; i++; }
    char b[48]; snprintf(b, sizeof(b), "%.1f %s", v, u[i]);
    return b;
}
static std::string fmt_pct(double p) {
    char b[32]; snprintf(b, sizeof(b), "%.1f%%", p); return b;
}
static std::string fmt_duration(double s) {
    long t = (long)s;
    long d = t / 86400; t %= 86400;
    long h = t / 3600;  t %= 3600;
    long m = t / 60;
    char b[48];
    if (d > 0) snprintf(b, sizeof(b), "%ldd %02ldh %02ldm", d, h, m);
    else       snprintf(b, sizeof(b), "%02ldh %02ldm", h, m);
    return b;
}

// ---------------------------------------------------------------------------
// History ring buffer
// ---------------------------------------------------------------------------
struct History {
    double v[HISTORY_MAX] = {0};
    int    len = 0;
    void push(double x) {
        if (len < HISTORY_MAX) { v[len++] = x; }
        else { memmove(v, v + 1, (HISTORY_MAX - 1) * sizeof(double)); v[HISTORY_MAX - 1] = x; }
    }
};

// ---------------------------------------------------------------------------
// Data collectors
// ---------------------------------------------------------------------------
struct CpuTimes { uint64_t idle = 0, total = 0; };

// Read aggregate + per-core jiffies from /proc/stat.
static void read_cpu(CpuTimes &agg, std::vector<CpuTimes> &cores) {
    cores.clear();
    std::ifstream f("/proc/stat");
    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind("cpu", 0) != 0) break;
        std::istringstream ss(line);
        std::string tag; ss >> tag;
        uint64_t user, nice, sys, idle, iowait, irq, softirq, steal;
        user = nice = sys = idle = iowait = irq = softirq = steal = 0;
        ss >> user >> nice >> sys >> idle >> iowait >> irq >> softirq >> steal;
        CpuTimes t;
        t.idle  = idle + iowait;
        t.total = user + nice + sys + idle + iowait + irq + softirq + steal;
        if (tag == "cpu") agg = t;
        else              cores.push_back(t);
    }
}

static double cpu_pct(const CpuTimes &a, const CpuTimes &b) {
    double dt = (double)(b.total - a.total);
    double di = (double)(b.idle  - a.idle);
    if (dt <= 0) return 0.0;
    double p = (1.0 - di / dt) * 100.0;
    return std::clamp(p, 0.0, 100.0);
}

// Average current CPU frequency across cores (MHz). 0 if unavailable.
static double read_cpu_mhz() {
    double sum = 0; int n = 0;
    DIR *d = opendir("/sys/devices/system/cpu");
    if (d) {
        struct dirent *e;
        while ((e = readdir(d))) {
            if (strncmp(e->d_name, "cpu", 3) != 0 || !isdigit((unsigned char)e->d_name[3]))
                continue;
            std::string p = std::string("/sys/devices/system/cpu/") + e->d_name +
                            "/cpufreq/scaling_cur_freq";
            std::ifstream f(p);
            long khz;
            if (f >> khz) { sum += khz / 1000.0; n++; }
        }
        closedir(d);
    }
    if (n) return sum / n;
    // Fallback: /proc/cpuinfo "cpu MHz"
    std::ifstream f("/proc/cpuinfo");
    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind("cpu MHz", 0) == 0) {
            auto pos = line.find(':');
            if (pos != std::string::npos) { sum += atof(line.c_str() + pos + 1); n++; }
        }
    }
    return n ? sum / n : 0.0;
}

static std::string read_cpu_model() {
    std::ifstream f("/proc/cpuinfo");
    std::string line;
    while (std::getline(f, line)) {
        if (line.rfind("model name", 0) == 0) {
            auto pos = line.find(':');
            if (pos != std::string::npos) {
                std::string s = line.substr(pos + 1);
                size_t a = s.find_first_not_of(" \t");
                if (a != std::string::npos) s = s.substr(a);
                return s;
            }
        }
    }
    return "Unknown CPU";
}

// CPU package temperature in °C. Prefers coretemp/k10temp "Package id 0",
// falls back to the x86_pkg_temp thermal zone, then any hwmon temp.
static double read_cpu_temp_c() {
    const char *prefer[] = {"coretemp", "k10temp", "zenpower", "cpu_thermal", nullptr};
    std::string best_name;
    double best = -1000.0;
    DIR *d = opendir("/sys/class/hwmon");
    if (d) {
        struct dirent *e;
        while ((e = readdir(d))) {
            if (e->d_name[0] == '.') continue;
            std::string base = std::string("/sys/class/hwmon/") + e->d_name;
            std::ifstream nf(base + "/name");
            std::string name; std::getline(nf, name);
            bool preferred = false;
            for (int i = 0; prefer[i]; i++) if (name == prefer[i]) preferred = true;

            // Look for a temp*_input, preferring the one labelled "Package".
            for (int i = 1; i <= 16; i++) {
                std::string in = base + "/temp" + std::to_string(i) + "_input";
                std::ifstream tf(in);
                long milli;
                if (!(tf >> milli)) continue;
                double c = milli / 1000.0;
                std::ifstream lf(base + "/temp" + std::to_string(i) + "_label");
                std::string label; std::getline(lf, label);
                bool pkg = label.find("Package") != std::string::npos ||
                           label.find("Tdie")    != std::string::npos;
                if (preferred && (pkg || best_name.empty())) {
                    if (pkg) { closedir(d); return c; }
                    if (best_name.empty()) { best = c; best_name = name; }
                }
                if (best < -500.0) { best = c; best_name = name; }
            }
        }
        closedir(d);
    }
    if (best > -500.0) return best;
    // Fallback: thermal zones
    std::ifstream tz("/sys/class/thermal/thermal_zone6/temp");
    long m;
    if (tz >> m) return m / 1000.0;
    return 0.0;
}

struct MemInfo { double total=0, avail=0, used=0, swap_total=0, swap_used=0, cached=0, buffers=0; };
static MemInfo read_mem() {
    std::map<std::string, double> kv;
    std::ifstream f("/proc/meminfo");
    std::string k; double val; std::string unit;
    std::string line;
    while (std::getline(f, line)) {
        std::istringstream ss(line);
        ss >> k >> val >> unit;
        if (!k.empty() && k.back() == ':') k.pop_back();
        kv[k] = val * 1024.0;  // kB -> bytes
    }
    MemInfo m;
    m.total      = kv["MemTotal"];
    m.avail      = kv.count("MemAvailable") ? kv["MemAvailable"] : kv["MemFree"];
    m.cached     = kv["Cached"];
    m.buffers    = kv["Buffers"];
    m.used       = m.total - m.avail;
    m.swap_total = kv["SwapTotal"];
    m.swap_used  = kv["SwapTotal"] - kv["SwapFree"];
    return m;
}

// Aggregate disk I/O across physical block devices (skip loop/ram/zram and
// partitions like nvme0n1p1 by only counting whole devices in /sys/block).
static void read_diskio(uint64_t &rd, uint64_t &wr) {
    rd = wr = 0;
    std::vector<std::string> whole;
    DIR *d = opendir("/sys/block");
    if (d) {
        struct dirent *e;
        while ((e = readdir(d))) {
            std::string n = e->d_name;
            if (n[0] == '.') continue;
            if (n.rfind("loop",0)==0 || n.rfind("ram",0)==0 || n.rfind("zram",0)==0) continue;
            whole.push_back(n);
        }
        closedir(d);
    }
    std::ifstream f("/proc/diskstats");
    std::string line;
    while (std::getline(f, line)) {
        std::istringstream ss(line);
        unsigned maj, min; std::string name;
        uint64_t r_ios, r_mrg, r_sec, r_tk, w_ios, w_mrg, w_sec;
        if (!(ss >> maj >> min >> name >> r_ios >> r_mrg >> r_sec >> r_tk
                 >> w_ios >> w_mrg >> w_sec)) continue;
        if (std::find(whole.begin(), whole.end(), name) == whole.end()) continue;
        rd += r_sec * 512;
        wr += w_sec * 512;
    }
}

struct FsUsage { std::string mount; double total=0, used=0; };
static std::vector<FsUsage> read_filesystems() {
    std::vector<FsUsage> out;
    std::ifstream f("/proc/mounts");
    std::string dev, mount, type, opts;
    int a, b;
    while (f >> dev >> mount >> type >> opts >> a >> b) {
        if (dev.rfind("/dev/", 0) != 0) continue;
        // Skip duplicate/uninteresting pseudo mounts
        if (type == "squashfs") continue;
        struct statvfs st;
        if (statvfs(mount.c_str(), &st) != 0) continue;
        double total = (double)st.f_blocks * st.f_frsize;
        double avail = (double)st.f_bavail * st.f_frsize;
        if (total < 1.0) continue;
        FsUsage u; u.mount = mount; u.total = total; u.used = total - avail;
        // De-dup by mount point
        bool dup = false;
        for (auto &e : out) if (e.mount == u.mount) dup = true;
        if (!dup) out.push_back(u);
    }
    std::sort(out.begin(), out.end(),
              [](const FsUsage&x, const FsUsage&y){ return x.total > y.total; });
    if (out.size() > 6) out.resize(6);
    return out;
}

// Pick the network interface tied to the default route; fallback to the
// non-loopback interface carrying the most traffic.
static std::string detect_iface() {
    std::ifstream r("/proc/net/route");
    std::string line; std::getline(r, line);  // header
    std::string iface, dest;
    while (std::getline(r, line)) {
        std::istringstream ss(line);
        std::string ifc, dst;
        ss >> ifc >> dst;
        if (dst == "00000000") return ifc;
    }
    // Fallback
    std::ifstream f("/proc/net/dev");
    std::string best; double bestv = -1;
    std::getline(f, line); std::getline(f, line);
    while (std::getline(f, line)) {
        auto c = line.find(':');
        if (c == std::string::npos) continue;
        std::string name = line.substr(0, c);
        name.erase(0, name.find_first_not_of(" \t"));
        if (name == "lo") continue;
        std::istringstream ss(line.substr(c + 1));
        double rx, t; ss >> rx;
        for (int i = 0; i < 7; i++) ss >> t;
        double tx; ss >> tx;
        if (rx + tx > bestv) { bestv = rx + tx; best = name; }
    }
    return best;
}

static void read_netdev(const std::string &iface, uint64_t &rx, uint64_t &tx) {
    rx = tx = 0;
    std::ifstream f("/proc/net/dev");
    std::string line;
    while (std::getline(f, line)) {
        auto c = line.find(':');
        if (c == std::string::npos) continue;
        std::string name = line.substr(0, c);
        name.erase(0, name.find_first_not_of(" \t"));
        if (name != iface) continue;
        std::istringstream ss(line.substr(c + 1));
        uint64_t v[16] = {0};
        for (int i = 0; i < 16 && (ss >> v[i]); i++) {}
        rx = v[0];   // bytes received
        tx = v[8];   // bytes transmitted
        return;
    }
}

// Count established TCP connections across IPv4 and IPv6.
static int count_connections() {
    int est = 0;
    const char *paths[] = {"/proc/net/tcp", "/proc/net/tcp6"};
    for (auto p : paths) {
        std::ifstream f(p);
        std::string line; std::getline(f, line);  // header
        while (std::getline(f, line)) {
            std::istringstream ss(line);
            std::string sl, local, rem, state;
            ss >> sl >> local >> rem >> state;
            if (state == "01") est++;  // TCP_ESTABLISHED
        }
    }
    return est;
}

static double read_uptime() {
    std::ifstream f("/proc/uptime");
    double up = 0; f >> up; return up;
}

// ---------------------------------------------------------------------------
// Application state
// ---------------------------------------------------------------------------
struct GraphSpec;  // fwd

struct AppState {
    GtkApplication *app = nullptr;
    GtkWidget *window   = nullptr;

    bool fahrenheit = false;
    GtkWidget *unit_btn = nullptr;

    bool tray_active = false;  // true if a system tray accepted our icon

    // --- Overview labels ---
    GtkWidget *ov_cpu=nullptr, *ov_temp=nullptr, *ov_mem=nullptr,
              *ov_disk=nullptr, *ov_net=nullptr;
    GtkWidget *ov_cpu_sub=nullptr, *ov_temp_sub=nullptr, *ov_mem_sub=nullptr,
              *ov_disk_sub=nullptr, *ov_net_sub=nullptr;
    GtkWidget *ov_uptime=nullptr;
    GtkWidget *ov_graph=nullptr;

    // --- CPU page ---
    GtkWidget *cpu_pct=nullptr, *cpu_temp=nullptr, *cpu_freq=nullptr,
              *cpu_l1=nullptr, *cpu_l5=nullptr, *cpu_l15=nullptr, *cpu_model=nullptr;
    GtkWidget *cpu_graph=nullptr, *cpu_cores=nullptr;

    // --- Memory page ---
    GtkWidget *mem_pct=nullptr, *mem_used=nullptr, *mem_avail=nullptr,
              *mem_cached=nullptr, *mem_swap=nullptr;
    GtkWidget *mem_graph=nullptr, *mem_bars=nullptr;

    // --- Disk page ---
    GtkWidget *disk_used=nullptr, *disk_read=nullptr, *disk_write=nullptr,
              *disk_total=nullptr;
    GtkWidget *disk_graph=nullptr, *disk_bars=nullptr;

    // --- Network page ---
    GtkWidget *net_down=nullptr, *net_up=nullptr, *net_conns=nullptr,
              *net_iface=nullptr, *net_rx_total=nullptr, *net_tx_total=nullptr;
    GtkWidget *net_graph=nullptr;

    // --- Histories ---
    History h_cpu, h_mem, h_dread, h_dwrite, h_nrx, h_ntx;

    // --- Collector bookkeeping ---
    CpuTimes              prev_agg;
    std::vector<CpuTimes> prev_cores;
    std::vector<double>   core_pct;

    uint64_t prev_drd=0, prev_dwr=0;
    uint64_t prev_rx=0,  prev_tx=0;
    uint64_t base_rx=0,  base_tx=0;       // session baseline
    gint64   last_us=0;
    std::string iface;

    std::vector<FsUsage> fs;
    bool first_tick = true;
};

// A graph spec is attached to each drawing area.
struct GraphSpec {
    AppState *s;
    History *a;  RGB ca;          // series A (required)
    History *b;  RGB cb; bool has_b = false;   // series B (optional)
    int mode;    // 0 = percent (0..100), 1 = speed (auto-scaled bytes/s)
};

// ---------------------------------------------------------------------------
// Cairo graph drawing (smooth area + line, Tokyo Night) — adapted from diskmon
// ---------------------------------------------------------------------------
static void rounded_rect(cairo_t *cr, double x, double y, double w, double h, double r) {
    cairo_new_sub_path(cr);
    cairo_arc(cr, x + w - r, y + r,     r, -G_PI/2, 0);
    cairo_arc(cr, x + w - r, y + h - r, r, 0,        G_PI/2);
    cairo_arc(cr, x + r,     y + h - r, r, G_PI/2,   G_PI);
    cairo_arc(cr, x + r,     y + r,     r, G_PI,     3*G_PI/2);
    cairo_close_path(cr);
}

static void series_path(cairo_t *cr, const double *v, int len, double dx,
                        double maxv, int h, bool area) {
    if (len < 2) return;
    double px[HISTORY_MAX], py[HISTORY_MAX];
    for (int i = 0; i < len; i++) {
        px[i] = i * dx;
        double y = h - (v[i] / maxv) * h;
        py[i] = std::clamp(y, 1.5, (double)h);
    }
    if (area) { cairo_move_to(cr, px[0], (double)h); cairo_line_to(cr, px[0], py[0]); }
    else        cairo_move_to(cr, px[0], py[0]);
    for (int i = 0; i < len - 1; i++) {
        double x0=px[i>0?i-1:i], y0=py[i>0?i-1:i];
        double x1=px[i], y1=py[i], x2=px[i+1], y2=py[i+1];
        double x3=px[i+2<len?i+2:i+1], y3=py[i+2<len?i+2:i+1];
        double c1x=x1+(x2-x0)/6.0, c1y=y1+(y2-y0)/6.0;
        double c2x=x2-(x3-x1)/6.0, c2y=y2-(y3-y1)/6.0;
        cairo_curve_to(cr, c1x, c1y, c2x, c2y, x2, y2);
    }
    if (area) { cairo_line_to(cr, px[len-1], (double)h); cairo_close_path(cr); }
}

static void draw_graph(GtkDrawingArea *, cairo_t *cr, int width, int height, gpointer data) {
    GraphSpec *g = static_cast<GraphSpec *>(data);

    rounded_rect(cr, 0, 0, width, height, 12);
    cairo_clip_preserve(cr);
    cairo_pattern_t *bg = cairo_pattern_create_linear(0, 0, 0, height);
    cairo_pattern_add_color_stop_rgb(bg, 0.0, 0.066, 0.072, 0.105);
    cairo_pattern_add_color_stop_rgb(bg, 1.0, 0.043, 0.047, 0.078);
    cairo_set_source(cr, bg); cairo_paint(cr); cairo_pattern_destroy(bg);

    // Grid
    cairo_set_source_rgba(cr, 0.32, 0.36, 0.52, 0.22);
    cairo_set_line_width(cr, 1.0);
    for (int i = 1; i < 4; i++) {
        double y = height * i / 4.0;
        cairo_move_to(cr, 0, y); cairo_line_to(cr, width, y); cairo_stroke(cr);
    }
    for (int i = 1; i < 6; i++) {
        double x = width * i / 6.0;
        cairo_move_to(cr, x, 0); cairo_line_to(cr, x, height); cairo_stroke(cr);
    }

    // Scale
    double maxv;
    std::string top, half, zero;
    if (g->mode == 0) {
        maxv = 100.0;
        top = "100%"; half = "50%"; zero = "0%";
    } else {
        maxv = 1024.0;
        for (int i = 0; i < g->a->len; i++) maxv = std::max(maxv, g->a->v[i]);
        if (g->has_b) for (int i = 0; i < g->b->len; i++) maxv = std::max(maxv, g->b->v[i]);
        maxv *= 1.15;
        top = fmt_speed(maxv); half = fmt_speed(maxv/2.0); zero = "0";
    }

    cairo_select_font_face(cr, "Inter", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_NORMAL);
    cairo_set_font_size(cr, 10.0);
    cairo_set_source_rgba(cr, 0.55, 0.58, 0.72, 0.9);
    cairo_move_to(cr, 10, 16);               cairo_show_text(cr, top.c_str());
    cairo_move_to(cr, 10, height/2.0 + 4);   cairo_show_text(cr, half.c_str());
    cairo_move_to(cr, 10, height - 9);       cairo_show_text(cr, zero.c_str());

    double dx = (double)width / (HISTORY_MAX - 1);
    struct S { History *h; RGB c; };
    std::vector<S> ss;
    if (g->has_b) { ss.push_back({g->b, g->cb}); ss.push_back({g->a, g->ca}); }
    else            ss.push_back({g->a, g->ca});

    for (auto &se : ss) {
        if (se.h->len < 2) continue;
        series_path(cr, se.h->v, se.h->len, dx, maxv, height, true);
        cairo_pattern_t *fill = cairo_pattern_create_linear(0, 0, 0, height);
        cairo_pattern_add_color_stop_rgba(fill, 0.0, se.c.r, se.c.g, se.c.b, 0.30);
        cairo_pattern_add_color_stop_rgba(fill, 1.0, se.c.r, se.c.g, se.c.b, 0.0);
        cairo_set_source(cr, fill); cairo_fill(cr); cairo_pattern_destroy(fill);

        series_path(cr, se.h->v, se.h->len, dx, maxv, height, false);
        cairo_set_line_join(cr, CAIRO_LINE_JOIN_ROUND);
        cairo_set_source_rgba(cr, se.c.r, se.c.g, se.c.b, 0.30);
        cairo_set_line_width(cr, 6.0); cairo_stroke_preserve(cr);
        cairo_set_source_rgb(cr, se.c.r, se.c.g, se.c.b);
        cairo_set_line_width(cr, 2.0); cairo_stroke(cr);

        double lx = (se.h->len - 1) * dx;
        double ly = std::clamp(height - (se.h->v[se.h->len-1] / maxv) * height, 1.5, (double)height);
        cairo_set_source_rgba(cr, se.c.r, se.c.g, se.c.b, 0.25);
        cairo_arc(cr, lx, ly, 5.0, 0, 2*G_PI); cairo_fill(cr);
        cairo_set_source_rgb(cr, se.c.r, se.c.g, se.c.b);
        cairo_arc(cr, lx, ly, 2.5, 0, 2*G_PI); cairo_fill(cr);
    }

    cairo_reset_clip(cr);
    rounded_rect(cr, 0.5, 0.5, width-1, height-1, 12);
    cairo_set_source_rgba(cr, 0.48, 0.55, 0.86, 0.35);
    cairo_set_line_width(cr, 1.0); cairo_stroke(cr);
}

// ---------------------------------------------------------------------------
// Per-core CPU bars
// ---------------------------------------------------------------------------
static void draw_cores(GtkDrawingArea *, cairo_t *cr, int width, int height, gpointer data) {
    AppState *s = static_cast<AppState *>(data);
    int n = (int)s->core_pct.size();
    if (n == 0) return;

    double gap = 6.0;
    double bw  = (width - gap * (n - 1)) / n;
    cairo_select_font_face(cr, "Inter", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
    cairo_set_font_size(cr, 9.0);

    for (int i = 0; i < n; i++) {
        double x = i * (bw + gap);
        double p = s->core_pct[i] / 100.0;
        double track_top = 16.0;
        double track_h   = height - 30.0;

        // Track
        rounded_rect(cr, x, track_top, bw, track_h, 4);
        cairo_set_source_rgba(cr, 0.20, 0.23, 0.34, 0.6);
        cairo_fill(cr);

        // Fill (green -> orange -> red by load)
        RGB c = COL_GREEN;
        if (p > 0.85) c = COL_RED; else if (p > 0.6) c = COL_ORANGE;
        double fh = track_h * p;
        rounded_rect(cr, x, track_top + (track_h - fh), bw, fh, 4);
        cairo_set_source_rgb(cr, c.r, c.g, c.b);
        cairo_fill(cr);

        // Labels
        cairo_set_source_rgba(cr, 0.69, 0.74, 0.90, 0.95);
        char lbl[16]; snprintf(lbl, sizeof(lbl), "%d", i);
        cairo_text_extents_t te; cairo_text_extents(cr, lbl, &te);
        cairo_move_to(cr, x + bw/2 - te.width/2, height - 4);
        cairo_show_text(cr, lbl);

        char pv[16]; snprintf(pv, sizeof(pv), "%d", (int)s->core_pct[i]);
        cairo_text_extents(cr, pv, &te);
        cairo_move_to(cr, x + bw/2 - te.width/2, 11);
        cairo_show_text(cr, pv);
    }
}

// ---------------------------------------------------------------------------
// Horizontal usage bars (memory breakdown / filesystems)
// ---------------------------------------------------------------------------
struct BarRow { std::string label; std::string value; double frac; RGB color; };

static void draw_bars(GtkDrawingArea *, cairo_t *cr, int width, int height, gpointer data) {
    std::vector<BarRow> *rows = static_cast<std::vector<BarRow> *>(data);
    int n = (int)rows->size();
    if (n == 0) return;

    double rowh = (double)height / n;
    double label_w = 110.0;
    double value_w = 96.0;
    double bx = label_w;
    double bw = width - label_w - value_w;
    if (bw < 40) { bw = width - label_w; value_w = 0; }

    cairo_select_font_face(cr, "Inter", CAIRO_FONT_SLANT_NORMAL, CAIRO_FONT_WEIGHT_BOLD);
    cairo_set_font_size(cr, 12.0);

    for (int i = 0; i < n; i++) {
        BarRow &r = (*rows)[i];
        double cy = i * rowh + rowh/2.0;
        double barh = std::min(16.0, rowh - 10.0);
        double by = cy - barh/2.0;

        // Label
        cairo_set_source_rgba(cr, 0.75, 0.79, 0.96, 0.95);
        cairo_move_to(cr, 0, cy + 4);
        cairo_show_text(cr, r.label.c_str());

        // Track
        rounded_rect(cr, bx, by, bw, barh, barh/2);
        cairo_set_source_rgba(cr, 0.20, 0.23, 0.34, 0.6);
        cairo_fill(cr);

        // Fill
        double fw = std::max(0.0, std::min(1.0, r.frac)) * bw;
        if (fw > 2) {
            rounded_rect(cr, bx, by, fw, barh, barh/2);
            RGB c = r.color;
            if (r.frac > 0.9) c = COL_RED; else if (r.frac > 0.75) c = COL_ORANGE;
            cairo_set_source_rgb(cr, c.r, c.g, c.b);
            cairo_fill(cr);
        }

        // Value
        if (value_w > 0) {
            cairo_set_source_rgba(cr, 0.69, 0.74, 0.90, 0.95);
            cairo_text_extents_t te; cairo_text_extents(cr, r.value.c_str(), &te);
            cairo_move_to(cr, width - te.width, cy + 4);
            cairo_show_text(cr, r.value.c_str());
        }
    }
}

// ---------------------------------------------------------------------------
// Temperature unit helper
// ---------------------------------------------------------------------------
static std::string fmt_temp(AppState *s, double c) {
    if (s->fahrenheit) { char b[32]; snprintf(b, sizeof(b), "%.0f °F", c*9.0/5.0+32.0); return b; }
    char b[32]; snprintf(b, sizeof(b), "%.0f °C", c); return b;
}

// ---------------------------------------------------------------------------
// UI construction helpers
// ---------------------------------------------------------------------------
static GtkWidget *make_card(const char *title, const char *accent_class,
                            const char *val_class, GtkWidget **out_val,
                            GtkWidget **out_sub) {
    GtkWidget *card = gtk_box_new(GTK_ORIENTATION_VERTICAL, 2);
    gtk_widget_add_css_class(card, "card");
    if (accent_class) gtk_widget_add_css_class(card, accent_class);
    gtk_widget_set_hexpand(card, TRUE);

    GtkWidget *lt = gtk_label_new(title);
    gtk_widget_add_css_class(lt, "stat-title");
    gtk_widget_set_halign(lt, GTK_ALIGN_START);

    GtkWidget *lv = gtk_label_new("—");
    gtk_widget_add_css_class(lv, "stat-val");
    if (val_class) gtk_widget_add_css_class(lv, val_class);
    gtk_widget_set_halign(lv, GTK_ALIGN_START);
    *out_val = lv;

    gtk_box_append(GTK_BOX(card), lt);
    gtk_box_append(GTK_BOX(card), lv);

    if (out_sub) {
        GtkWidget *ls = gtk_label_new("");
        gtk_widget_add_css_class(ls, "stat-sub");
        gtk_widget_set_halign(ls, GTK_ALIGN_START);
        gtk_box_append(GTK_BOX(card), ls);
        *out_sub = ls;
    }
    return card;
}

static GtkWidget *make_mini(const char *title, GtkWidget **out_val) {
    GtkWidget *box = gtk_box_new(GTK_ORIENTATION_VERTICAL, 1);
    gtk_widget_set_hexpand(box, TRUE);
    GtkWidget *t = gtk_label_new(title);
    gtk_widget_add_css_class(t, "grid-label-title");
    gtk_widget_set_halign(t, GTK_ALIGN_START);
    GtkWidget *v = gtk_label_new("—");
    gtk_widget_add_css_class(v, "grid-label-val");
    gtk_widget_set_halign(v, GTK_ALIGN_START);
    *out_val = v;
    gtk_box_append(GTK_BOX(box), t);
    gtk_box_append(GTK_BOX(box), v);
    return box;
}

static GtkWidget *make_graph_panel(const char *title, GtkWidget **area,
                                   GraphSpec *spec, int min_h) {
    GtkWidget *panel = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_add_css_class(panel, "panel");
    gtk_widget_set_hexpand(panel, TRUE);
    gtk_widget_set_vexpand(panel, TRUE);
    GtkWidget *t = gtk_label_new(title);
    gtk_widget_add_css_class(t, "graph-title");
    gtk_widget_set_halign(t, GTK_ALIGN_START);
    gtk_box_append(GTK_BOX(panel), t);

    GtkWidget *da = gtk_drawing_area_new();
    gtk_widget_set_vexpand(da, TRUE);
    gtk_widget_set_hexpand(da, TRUE);
    gtk_drawing_area_set_content_height(GTK_DRAWING_AREA(da), min_h);
    gtk_drawing_area_set_draw_func(GTK_DRAWING_AREA(da), draw_graph, spec, nullptr);
    gtk_box_append(GTK_BOX(panel), da);
    *area = da;
    return panel;
}

// ---------------------------------------------------------------------------
// Bar-row storage (heap, so draw funcs can read them between ticks)
// ---------------------------------------------------------------------------
static std::vector<BarRow> g_mem_rows;
static std::vector<BarRow> g_fs_rows;

// GraphSpecs (one per drawing area; kept alive for program lifetime)
static GraphSpec gs_ov, gs_cpu, gs_mem, gs_disk, gs_net;

// ---------------------------------------------------------------------------
// Periodic tick — collect everything, update whichever widgets exist
// ---------------------------------------------------------------------------
static gboolean on_tick(gpointer data) {
    AppState *s = static_cast<AppState *>(data);
    gint64 now_us = g_get_monotonic_time();
    double dt = s->last_us ? (now_us - s->last_us) / 1e6 : 1.0;
    if (dt <= 0) dt = 1.0;

    // ---- CPU ----
    CpuTimes agg; std::vector<CpuTimes> cores;
    read_cpu(agg, cores);
    double cpu = 0;
    if (!s->first_tick) cpu = cpu_pct(s->prev_agg, agg);
    s->core_pct.assign(cores.size(), 0.0);
    if (!s->first_tick && s->prev_cores.size() == cores.size())
        for (size_t i = 0; i < cores.size(); i++)
            s->core_pct[i] = cpu_pct(s->prev_cores[i], cores[i]);
    s->prev_agg = agg; s->prev_cores = cores;

    double temp = read_cpu_temp_c();
    double mhz  = read_cpu_mhz();

    double l1=0,l5=0,l15=0;
    { std::ifstream f("/proc/loadavg"); f >> l1 >> l5 >> l15; }

    // ---- Memory ----
    MemInfo mem = read_mem();
    double mem_pct = mem.total ? mem.used / mem.total * 100.0 : 0.0;

    // ---- Disk I/O ----
    uint64_t drd, dwr; read_diskio(drd, dwr);
    double dread=0, dwrite=0;
    if (!s->first_tick) {
        dread  = (drd > s->prev_drd) ? (drd - s->prev_drd) / dt : 0;
        dwrite = (dwr > s->prev_dwr) ? (dwr - s->prev_dwr) / dt : 0;
    }
    s->prev_drd = drd; s->prev_dwr = dwr;

    s->fs = read_filesystems();
    double disk_used_b=0, disk_total_b=0;
    for (auto &u : s->fs) { disk_used_b += u.used; disk_total_b += u.total; }
    double disk_pct = disk_total_b ? disk_used_b/disk_total_b*100.0 : 0.0;

    // ---- Network ----
    if (s->iface.empty()) s->iface = detect_iface();
    uint64_t rx, tx; read_netdev(s->iface, rx, tx);
    double down=0, up=0;
    if (!s->first_tick) {
        down = (rx > s->prev_rx) ? (rx - s->prev_rx) / dt : 0;
        up   = (tx > s->prev_tx) ? (tx - s->prev_tx) / dt : 0;
    } else { s->base_rx = rx; s->base_tx = tx; }
    s->prev_rx = rx; s->prev_tx = tx;
    int conns = count_connections();

    double uptime = read_uptime();

    s->last_us = now_us;
    s->first_tick = false;

    // ---- Push histories ----
    s->h_cpu.push(cpu);
    s->h_mem.push(mem_pct);
    s->h_dread.push(dread);
    s->h_dwrite.push(dwrite);
    s->h_nrx.push(down);
    s->h_ntx.push(up);

    // ---- Update Overview ----
    if (s->ov_cpu)  gtk_label_set_text(GTK_LABEL(s->ov_cpu),  fmt_pct(cpu).c_str());
    if (s->ov_cpu_sub) {
        char b[64]; snprintf(b, sizeof(b), "%.0f cores · %.2f GHz", (double)cores.size(), mhz/1000.0);
        gtk_label_set_text(GTK_LABEL(s->ov_cpu_sub), b);
    }
    if (s->ov_temp) gtk_label_set_text(GTK_LABEL(s->ov_temp), fmt_temp(s, temp).c_str());
    if (s->ov_temp_sub) gtk_label_set_text(GTK_LABEL(s->ov_temp_sub), "CPU package");
    if (s->ov_mem)  gtk_label_set_text(GTK_LABEL(s->ov_mem),  fmt_pct(mem_pct).c_str());
    if (s->ov_mem_sub) {
        std::string b = fmt_bytes(mem.used) + " / " + fmt_bytes(mem.total);
        gtk_label_set_text(GTK_LABEL(s->ov_mem_sub), b.c_str());
    }
    if (s->ov_disk) gtk_label_set_text(GTK_LABEL(s->ov_disk), fmt_pct(disk_pct).c_str());
    if (s->ov_disk_sub) {
        std::string b = fmt_bytes(disk_used_b) + " / " + fmt_bytes(disk_total_b);
        gtk_label_set_text(GTK_LABEL(s->ov_disk_sub), b.c_str());
    }
    if (s->ov_net) {
        std::string b = "↓ " + fmt_speed(down);
        gtk_label_set_text(GTK_LABEL(s->ov_net), b.c_str());
    }
    if (s->ov_net_sub) {
        std::string b = "↑ " + fmt_speed(up) + " · " + std::to_string(conns) + " conn";
        gtk_label_set_text(GTK_LABEL(s->ov_net_sub), b.c_str());
    }
    if (s->ov_uptime) gtk_label_set_text(GTK_LABEL(s->ov_uptime), fmt_duration(uptime).c_str());

    // ---- Update CPU page ----
    if (s->cpu_pct)  gtk_label_set_text(GTK_LABEL(s->cpu_pct),  fmt_pct(cpu).c_str());
    if (s->cpu_temp) gtk_label_set_text(GTK_LABEL(s->cpu_temp), fmt_temp(s, temp).c_str());
    if (s->cpu_freq) { char b[32]; snprintf(b,sizeof(b),"%.2f GHz", mhz/1000.0);
                       gtk_label_set_text(GTK_LABEL(s->cpu_freq), b); }
    if (s->cpu_l1)   { char b[16]; snprintf(b,sizeof(b),"%.2f", l1);  gtk_label_set_text(GTK_LABEL(s->cpu_l1), b); }
    if (s->cpu_l5)   { char b[16]; snprintf(b,sizeof(b),"%.2f", l5);  gtk_label_set_text(GTK_LABEL(s->cpu_l5), b); }
    if (s->cpu_l15)  { char b[16]; snprintf(b,sizeof(b),"%.2f", l15); gtk_label_set_text(GTK_LABEL(s->cpu_l15), b); }

    // ---- Update Memory page ----
    if (s->mem_pct)    gtk_label_set_text(GTK_LABEL(s->mem_pct), fmt_pct(mem_pct).c_str());
    if (s->mem_used)   gtk_label_set_text(GTK_LABEL(s->mem_used), fmt_bytes(mem.used).c_str());
    if (s->mem_avail)  gtk_label_set_text(GTK_LABEL(s->mem_avail), fmt_bytes(mem.avail).c_str());
    if (s->mem_cached) gtk_label_set_text(GTK_LABEL(s->mem_cached), fmt_bytes(mem.cached + mem.buffers).c_str());
    if (s->mem_swap) {
        std::string b = mem.swap_total > 0
            ? fmt_bytes(mem.swap_used) + " / " + fmt_bytes(mem.swap_total)
            : std::string("none");
        gtk_label_set_text(GTK_LABEL(s->mem_swap), b.c_str());
    }
    g_mem_rows.clear();
    g_mem_rows.push_back({"Used",     fmt_bytes(mem.used),            mem.total?mem.used/mem.total:0,           COL_PURPLE});
    g_mem_rows.push_back({"Cache/Buf",fmt_bytes(mem.cached+mem.buffers), mem.total?(mem.cached+mem.buffers)/mem.total:0, COL_CYAN});
    g_mem_rows.push_back({"Available",fmt_bytes(mem.avail),           mem.total?mem.avail/mem.total:0,          COL_GREEN});
    if (mem.swap_total > 0)
        g_mem_rows.push_back({"Swap", fmt_bytes(mem.swap_used), mem.swap_used/mem.swap_total, COL_ORANGE});

    // ---- Update Disk page ----
    if (s->disk_used)  gtk_label_set_text(GTK_LABEL(s->disk_used),  fmt_pct(disk_pct).c_str());
    if (s->disk_read)  gtk_label_set_text(GTK_LABEL(s->disk_read),  fmt_speed(dread).c_str());
    if (s->disk_write) gtk_label_set_text(GTK_LABEL(s->disk_write), fmt_speed(dwrite).c_str());
    if (s->disk_total) gtk_label_set_text(GTK_LABEL(s->disk_total), fmt_bytes(disk_total_b).c_str());
    g_fs_rows.clear();
    for (auto &u : s->fs) {
        double frac = u.total ? u.used/u.total : 0;
        std::string val = fmt_bytes(u.used) + "/" + fmt_bytes(u.total);
        g_fs_rows.push_back({u.mount, val, frac, COL_BLUE});
    }

    // ---- Update Network page ----
    if (s->net_down)  gtk_label_set_text(GTK_LABEL(s->net_down),  fmt_speed(down).c_str());
    if (s->net_up)    gtk_label_set_text(GTK_LABEL(s->net_up),    fmt_speed(up).c_str());
    if (s->net_conns) gtk_label_set_text(GTK_LABEL(s->net_conns), std::to_string(conns).c_str());
    if (s->net_iface) gtk_label_set_text(GTK_LABEL(s->net_iface), s->iface.empty()?"—":s->iface.c_str());
    if (s->net_rx_total) gtk_label_set_text(GTK_LABEL(s->net_rx_total), fmt_bytes((double)(rx - s->base_rx)).c_str());
    if (s->net_tx_total) gtk_label_set_text(GTK_LABEL(s->net_tx_total), fmt_bytes((double)(tx - s->base_tx)).c_str());

    // ---- Redraw graphs ----
    if (s->ov_graph)   gtk_widget_queue_draw(s->ov_graph);
    if (s->cpu_graph)  gtk_widget_queue_draw(s->cpu_graph);
    if (s->cpu_cores)  gtk_widget_queue_draw(s->cpu_cores);
    if (s->mem_graph)  gtk_widget_queue_draw(s->mem_graph);
    if (s->mem_bars)   gtk_widget_queue_draw(s->mem_bars);
    if (s->disk_graph) gtk_widget_queue_draw(s->disk_graph);
    if (s->disk_bars)  gtk_widget_queue_draw(s->disk_bars);
    if (s->net_graph)  gtk_widget_queue_draw(s->net_graph);

    return G_SOURCE_CONTINUE;
}

// ---------------------------------------------------------------------------
// Page builders
// ---------------------------------------------------------------------------
static GtkWidget *build_overview(AppState *s) {
    GtkWidget *root = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_add_css_class(root, "page");

    // Row of summary cards
    GtkWidget *cards = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_box_set_homogeneous(GTK_BOX(cards), TRUE);
    GtkWidget *c1 = make_card("CPU",     "card-blue",   "stat-val-blue",   &s->ov_cpu,  &s->ov_cpu_sub);
    GtkWidget *c2 = make_card("TEMP",    "card-orange", "stat-val-orange", &s->ov_temp, &s->ov_temp_sub);
    GtkWidget *c3 = make_card("MEMORY",  "card-purple", "stat-val-purple", &s->ov_mem,  &s->ov_mem_sub);
    GtkWidget *c4 = make_card("DISK",    "card-green",  "stat-val-green",  &s->ov_disk, &s->ov_disk_sub);
    GtkWidget *c5 = make_card("NETWORK", "card-cyan",   "stat-val-cyan",   &s->ov_net,  &s->ov_net_sub);
    gtk_box_append(GTK_BOX(cards), c1); gtk_box_append(GTK_BOX(cards), c2);
    gtk_box_append(GTK_BOX(cards), c3); gtk_box_append(GTK_BOX(cards), c4);
    gtk_box_append(GTK_BOX(cards), c5);
    gtk_box_append(GTK_BOX(root), cards);

    // Combined CPU+RAM graph
    gs_ov = {s, &s->h_cpu, COL_BLUE, &s->h_mem, COL_PURPLE, true, 0};
    GtkWidget *panel = make_graph_panel("CPU  ·  MEMORY   (%)", &s->ov_graph, &gs_ov, 200);
    gtk_box_append(GTK_BOX(root), panel);

    // Uptime strip
    GtkWidget *strip = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_widget_add_css_class(strip, "panel");
    gtk_box_append(GTK_BOX(strip), make_mini("UPTIME", &s->ov_uptime));
    GtkWidget *modlbl;
    GtkWidget *modbox = make_mini("PROCESSOR", &modlbl);
    gtk_label_set_text(GTK_LABEL(modlbl), read_cpu_model().c_str());
    gtk_label_set_ellipsize(GTK_LABEL(modlbl), PANGO_ELLIPSIZE_END);
    gtk_widget_set_hexpand(modbox, TRUE);
    gtk_box_append(GTK_BOX(strip), modbox);
    gtk_box_append(GTK_BOX(root), strip);

    return root;
}

static GtkWidget *build_cpu(AppState *s) {
    GtkWidget *root = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_widget_add_css_class(root, "page");

    // Left: stat cards (vertical)
    GtkWidget *left = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_set_size_request(left, 240, -1);
    GtkWidget *c1 = make_card("CPU USAGE", "card-blue", "stat-val-blue", &s->cpu_pct, nullptr);
    GtkWidget *c2 = make_card("TEMPERATURE", "card-orange", "stat-val-orange", &s->cpu_temp, nullptr);
    gtk_box_append(GTK_BOX(left), c1);
    gtk_box_append(GTK_BOX(left), c2);

    GtkWidget *grid = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_widget_add_css_class(grid, "panel");
    gtk_box_append(GTK_BOX(grid), make_mini("FREQ",  &s->cpu_freq));
    gtk_box_append(GTK_BOX(grid), make_mini("LOAD 1m",  &s->cpu_l1));
    gtk_box_append(GTK_BOX(left), grid);
    GtkWidget *grid2 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_widget_add_css_class(grid2, "panel");
    gtk_box_append(GTK_BOX(grid2), make_mini("LOAD 5m",  &s->cpu_l5));
    gtk_box_append(GTK_BOX(grid2), make_mini("LOAD 15m", &s->cpu_l15));
    gtk_box_append(GTK_BOX(left), grid2);
    gtk_box_append(GTK_BOX(root), left);

    // Right: graph + per-core bars (vertical)
    GtkWidget *right = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_set_hexpand(right, TRUE);
    gs_cpu = {s, &s->h_cpu, COL_BLUE, nullptr, COL_BLUE, false, 0};
    GtkWidget *panel = make_graph_panel("CPU UTILISATION  (%)", &s->cpu_graph, &gs_cpu, 170);
    gtk_box_append(GTK_BOX(right), panel);

    GtkWidget *cpanel = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_add_css_class(cpanel, "panel");
    GtkWidget *ct = gtk_label_new("PER-CORE LOAD  (%)");
    gtk_widget_add_css_class(ct, "graph-title");
    gtk_widget_set_halign(ct, GTK_ALIGN_START);
    gtk_box_append(GTK_BOX(cpanel), ct);
    s->cpu_cores = gtk_drawing_area_new();
    gtk_widget_set_hexpand(s->cpu_cores, TRUE);
    gtk_drawing_area_set_content_height(GTK_DRAWING_AREA(s->cpu_cores), 120);
    gtk_drawing_area_set_draw_func(GTK_DRAWING_AREA(s->cpu_cores), draw_cores, s, nullptr);
    gtk_box_append(GTK_BOX(cpanel), s->cpu_cores);
    gtk_box_append(GTK_BOX(right), cpanel);
    gtk_box_append(GTK_BOX(root), right);

    return root;
}

static GtkWidget *build_memory(AppState *s) {
    GtkWidget *root = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_widget_add_css_class(root, "page");

    GtkWidget *left = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_set_size_request(left, 240, -1);
    gtk_box_append(GTK_BOX(left), make_card("MEMORY USED", "card-purple", "stat-val-purple", &s->mem_pct, nullptr));
    GtkWidget *g1 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_widget_add_css_class(g1, "panel");
    gtk_box_append(GTK_BOX(g1), make_mini("USED", &s->mem_used));
    gtk_box_append(GTK_BOX(g1), make_mini("AVAILABLE", &s->mem_avail));
    gtk_box_append(GTK_BOX(left), g1);
    GtkWidget *g2 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_widget_add_css_class(g2, "panel");
    gtk_box_append(GTK_BOX(g2), make_mini("CACHE", &s->mem_cached));
    gtk_box_append(GTK_BOX(g2), make_mini("SWAP", &s->mem_swap));
    gtk_box_append(GTK_BOX(left), g2);
    gtk_box_append(GTK_BOX(root), left);

    GtkWidget *right = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_set_hexpand(right, TRUE);
    gs_mem = {s, &s->h_mem, COL_PURPLE, nullptr, COL_PURPLE, false, 0};
    gtk_box_append(GTK_BOX(right), make_graph_panel("MEMORY USAGE  (%)", &s->mem_graph, &gs_mem, 170));

    GtkWidget *bpanel = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_add_css_class(bpanel, "panel");
    GtkWidget *bt = gtk_label_new("BREAKDOWN");
    gtk_widget_add_css_class(bt, "graph-title");
    gtk_widget_set_halign(bt, GTK_ALIGN_START);
    gtk_box_append(GTK_BOX(bpanel), bt);
    s->mem_bars = gtk_drawing_area_new();
    gtk_widget_set_hexpand(s->mem_bars, TRUE);
    gtk_drawing_area_set_content_height(GTK_DRAWING_AREA(s->mem_bars), 130);
    gtk_drawing_area_set_draw_func(GTK_DRAWING_AREA(s->mem_bars), draw_bars, &g_mem_rows, nullptr);
    gtk_box_append(GTK_BOX(bpanel), s->mem_bars);
    gtk_box_append(GTK_BOX(right), bpanel);
    gtk_box_append(GTK_BOX(root), right);

    return root;
}

static GtkWidget *build_disk(AppState *s) {
    GtkWidget *root = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_widget_add_css_class(root, "page");

    GtkWidget *left = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_set_size_request(left, 240, -1);
    gtk_box_append(GTK_BOX(left), make_card("DISK USED", "card-blue", "stat-val-blue", &s->disk_used, nullptr));
    gtk_box_append(GTK_BOX(left), make_card("READ", "card-green", "stat-val-green", &s->disk_read, nullptr));
    gtk_box_append(GTK_BOX(left), make_card("WRITE", "card-red", "stat-val-red", &s->disk_write, nullptr));
    GtkWidget *g1 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_widget_add_css_class(g1, "panel");
    gtk_box_append(GTK_BOX(g1), make_mini("TOTAL CAPACITY", &s->disk_total));
    gtk_box_append(GTK_BOX(left), g1);
    gtk_box_append(GTK_BOX(root), left);

    GtkWidget *right = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_set_hexpand(right, TRUE);
    gs_disk = {s, &s->h_dread, COL_GREEN, &s->h_dwrite, COL_RED, true, 1};
    gtk_box_append(GTK_BOX(right), make_graph_panel("DISK I/O  ·  read / write", &s->disk_graph, &gs_disk, 170));

    GtkWidget *bpanel = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_widget_add_css_class(bpanel, "panel");
    GtkWidget *bt = gtk_label_new("FILESYSTEMS");
    gtk_widget_add_css_class(bt, "graph-title");
    gtk_widget_set_halign(bt, GTK_ALIGN_START);
    gtk_box_append(GTK_BOX(bpanel), bt);
    s->disk_bars = gtk_drawing_area_new();
    gtk_widget_set_hexpand(s->disk_bars, TRUE);
    gtk_drawing_area_set_content_height(GTK_DRAWING_AREA(s->disk_bars), 150);
    gtk_drawing_area_set_draw_func(GTK_DRAWING_AREA(s->disk_bars), draw_bars, &g_fs_rows, nullptr);
    gtk_box_append(GTK_BOX(bpanel), s->disk_bars);
    gtk_box_append(GTK_BOX(right), bpanel);
    gtk_box_append(GTK_BOX(root), right);

    return root;
}

static GtkWidget *build_network(AppState *s) {
    GtkWidget *root = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 12);
    gtk_widget_add_css_class(root, "page");

    GtkWidget *left = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_set_size_request(left, 240, -1);
    gtk_box_append(GTK_BOX(left), make_card("DOWNLOAD", "card-cyan", "stat-val-cyan", &s->net_down, nullptr));
    gtk_box_append(GTK_BOX(left), make_card("UPLOAD", "card-orange", "stat-val-orange", &s->net_up, nullptr));
    GtkWidget *g1 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_widget_add_css_class(g1, "panel");
    gtk_box_append(GTK_BOX(g1), make_mini("INTERFACE", &s->net_iface));
    gtk_box_append(GTK_BOX(g1), make_mini("CONNECTIONS", &s->net_conns));
    gtk_box_append(GTK_BOX(left), g1);
    GtkWidget *g2 = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 10);
    gtk_widget_add_css_class(g2, "panel");
    gtk_box_append(GTK_BOX(g2), make_mini("SESSION ↓", &s->net_rx_total));
    gtk_box_append(GTK_BOX(g2), make_mini("SESSION ↑", &s->net_tx_total));
    gtk_box_append(GTK_BOX(left), g2);
    gtk_box_append(GTK_BOX(root), left);

    GtkWidget *right = gtk_box_new(GTK_ORIENTATION_VERTICAL, 12);
    gtk_widget_set_hexpand(right, TRUE);
    gs_net = {s, &s->h_nrx, COL_CYAN, &s->h_ntx, COL_ORANGE, true, 1};
    gtk_box_append(GTK_BOX(right), make_graph_panel("NETWORK THROUGHPUT  ·  down / up", &s->net_graph, &gs_net, 280));
    gtk_box_append(GTK_BOX(root), right);

    return root;
}

// ---------------------------------------------------------------------------
// Unit toggle
// ---------------------------------------------------------------------------
static void on_unit_toggle(GtkButton *btn, gpointer data) {
    AppState *s = static_cast<AppState *>(data);
    s->fahrenheit = !s->fahrenheit;
    gtk_button_set_label(btn, s->fahrenheit ? "°F" : "°C");
}

// ---------------------------------------------------------------------------
// Page entry point — build the Vitals page for the unified Sentinel window.
//
// Returns a vbox holding the page's own sub-tab switcher (Overview / CPU /
// Memory / Disk / Network) and the °C/°F toggle on a thin toolbar, above the
// content stack. The shell (main.cpp) owns the window, the top-level
// Vitals/Firewall/Posture switcher, the tray and the About dialog, so this page
// is fully self-contained: it just builds widgets and runs its own 1 Hz timer.
// ---------------------------------------------------------------------------
static AppState g_vit;   // single instance for the unified app

GtkWidget *vitals_build(GtkWindow *parent) {
    AppState *s = &g_vit;
    s->window = GTK_WIDGET(parent);   // used only for transient dialogs, if any

    GtkWidget *stack = gtk_stack_new();
    gtk_stack_set_transition_type(GTK_STACK(stack), GTK_STACK_TRANSITION_TYPE_CROSSFADE);
    gtk_stack_add_titled(GTK_STACK(stack), build_overview(s), "overview", "Overview");
    gtk_stack_add_titled(GTK_STACK(stack), build_cpu(s),      "cpu",      "CPU");
    gtk_stack_add_titled(GTK_STACK(stack), build_memory(s),   "memory",   "Memory");
    gtk_stack_add_titled(GTK_STACK(stack), build_disk(s),     "disk",     "Disk");
    gtk_stack_add_titled(GTK_STACK(stack), build_network(s),  "network",  "Network");
    gtk_widget_set_vexpand(stack, TRUE);

    // Thin toolbar: sub-tab switcher on the left, unit toggle on the right.
    GtkWidget *bar = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 8);
    gtk_widget_set_margin_start(bar, 12);
    gtk_widget_set_margin_end(bar, 12);
    gtk_widget_set_margin_top(bar, 10);

    GtkWidget *switcher = gtk_stack_switcher_new();
    gtk_stack_switcher_set_stack(GTK_STACK_SWITCHER(switcher), GTK_STACK(stack));
    gtk_box_append(GTK_BOX(bar), switcher);

    GtkWidget *spacer = gtk_box_new(GTK_ORIENTATION_HORIZONTAL, 0);
    gtk_widget_set_hexpand(spacer, TRUE);
    gtk_box_append(GTK_BOX(bar), spacer);

    s->unit_btn = gtk_button_new_with_label("°C");
    gtk_widget_set_tooltip_text(s->unit_btn, "Toggle temperature unit (°C / °F)");
    g_signal_connect(s->unit_btn, "clicked", G_CALLBACK(on_unit_toggle), s);
    gtk_widget_set_valign(s->unit_btn, GTK_ALIGN_CENTER);
    gtk_box_append(GTK_BOX(bar), s->unit_btn);

    GtkWidget *root = gtk_box_new(GTK_ORIENTATION_VERTICAL, 0);
    gtk_box_append(GTK_BOX(root), bar);
    gtk_box_append(GTK_BOX(root), stack);

    on_tick(s);                       // prime values immediately
    g_timeout_add(1000, on_tick, s);  // refresh once a second
    return root;
}
