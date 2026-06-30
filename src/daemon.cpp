// sentinel-daemon — privileged backend for Sentinel (root).
//
// Two jobs over one Unix socket (/run/sentinel.sock):
//
//   1. FIREWALL (ported from Warden): an nftables rule diverts every *new*
//      outbound TCP connection to NFQUEUE; the daemon attributes the owning
//      process, consults the rule store, and asks the GUI on a miss.
//
//   2. POSTURE (ported from Envision): on an interval it re-runs the full
//      security-posture scan on a worker thread, frames a fresh snapshot to the
//      GUI, and DIFFS against the previous result so newly-appeared problems
//      (a port opens, a service fails, a SUID binary lands) surface live as
//      change alerts. This is what turns Envision's one-shot audit into the
//      "real-time checks" the unified tool is about.
//
// The firewall poll loop must never block, so posture scans — which include a
// filesystem-wide SUID/world-writable sweep — run on a detached worker thread.
// The worker only produces a ScanReport; all socket writes and diffing happen
// back on the main thread, keeping the single-threaded socket model intact.
//
// Author: Jean-Francois Lachance-Caumartin

#ifndef _GNU_SOURCE
#define _GNU_SOURCE            // struct ucred / SO_PEERCRED
#endif
#include <arpa/inet.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/un.h>
#include <sys/wait.h>
#include <fcntl.h>
#include <poll.h>
#include <unistd.h>
#include <dirent.h>
#include <ctype.h>
#include <linux/netlink.h>     // NETLINK_NO_ENOBUFS, NETLINK_CONNECTOR
#include <linux/connector.h>   // cn_msg, CN_IDX_PROC / CN_VAL_PROC
#include <linux/cn_proc.h>     // proc_event, PROC_CN_MCAST_LISTEN
#include <signal.h>

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cerrno>
#include <ctime>
#include <atomic>
#include <deque>
#include <map>
#include <mutex>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

#include <linux/netfilter.h>   // NF_ACCEPT / NF_DROP
extern "C" {
#include <libnetfilter_queue/libnetfilter_queue.h>
}

#include "sentinel_proto.h"
#include "scan.hpp"
#include "sha256.h"

// ---------------------------------------------------------------------------
// Global state (single-threaded main loop, so plain globals are fine)
// ---------------------------------------------------------------------------
static int g_client_fd = -1;          // connected GUI, or -1
static uint32_t g_next_id = 1;        // monotonically rising prompt id
static volatile sig_atomic_t g_stop = 0;

struct Rule { bool allow; std::string sha; };
static std::map<std::string, Rule> g_rules;   // exe path -> rule

struct Conn {                                 // a resolved outbound attempt
    std::string proto = "tcp";
    int         pid   = -1;
    std::string comm  = "?";
    std::string exe   = "?";
    std::string dst_ip;
    uint16_t    dst_port = 0;
};

static struct nfq_q_handle *g_qh = nullptr;   // for deferred (async) verdicts
static uid_t g_owner_uid = (uid_t)-1;         // UID allowed on the control socket
static std::string g_rx;                      // accumulated bytes from the GUI

// A connection held in NFQUEUE while we wait for the user to decide.
struct Pending { uint32_t pkt_id; Conn conn; long deadline_ms; };
static std::unordered_map<uint32_t, Pending> g_pending;   // ask id -> held packet

// Cache of exe-path -> SHA-256, keyed on size+mtime so we hash a binary once
// rather than on every connection it makes.
struct HashEntry { time_t mtime; off_t size; std::string sha; };
static std::unordered_map<std::string, HashEntry> g_hash_cache;

// ---- posture scanning state ----
static std::mutex          g_scan_mtx;            // guards g_scan_ready
static ScanReport         *g_scan_ready = nullptr;// worker hands a finished scan here
static std::atomic<bool>   g_scan_inflight{false};// a worker thread is running
static long                g_scan_interval_ms = SENTINEL_SCAN_INTERVAL_S * 1000L;
static long                g_last_scan_ms = -1;   // monotonic time of last kick
static std::map<std::string,int> g_prev_sev;      // category|title -> severity, last scan
static bool                g_have_prev = false;
static std::string         g_last_snapshot;       // framed PBEGIN..PEND, replayed on connect

// ---- live watchers state (process-exec + auth/login) ----
static int   g_exec_fd  = -1;          // proc-connector netlink socket, or -1 if unavailable
static pid_t g_auth_pid = -1;          // child running `journalctl -f`, or -1
static int   g_auth_fd  = -1;          // its stdout pipe, or -1 if unavailable
static std::string g_auth_rx;          // accumulated partial line from the auth pipe

// ---------------------------------------------------------------------------
// nftables plumbing
// ---------------------------------------------------------------------------
static int run(const char *cmd) { return system(cmd); }

static void install_nft() {
    // A dedicated table keeps our rules isolated and trivially removable. The
    // `bypass` flag means: if this daemon is not listening on the queue, accept
    // the packet rather than stall the connection — fail-open by design.
    run("nft add table inet " SENTINEL_NFT_TABLE " 2>/dev/null");
    run("nft add chain inet " SENTINEL_NFT_TABLE
        " out '{ type filter hook output priority 0 ; }' 2>/dev/null");
    run("nft flush chain inet " SENTINEL_NFT_TABLE " out 2>/dev/null");
    run("nft add rule inet " SENTINEL_NFT_TABLE " out oifname lo accept");
    run("nft add rule inet " SENTINEL_NFT_TABLE " out meta l4proto != tcp accept");
    run("nft add rule inet " SENTINEL_NFT_TABLE " out ct state established,related accept");
    char buf[200];
    snprintf(buf, sizeof(buf),
             "nft add rule inet " SENTINEL_NFT_TABLE
             " out ct state new queue num %d bypass", SENTINEL_QUEUE_NUM);
    run(buf);
}

static void remove_nft() { run("nft delete table inet " SENTINEL_NFT_TABLE " 2>/dev/null"); }

// ---------------------------------------------------------------------------
// Rule store (/etc/sentinel/rules.conf): "allow|deny <sha256|-> <exe path>"
// ---------------------------------------------------------------------------
static void load_rules() {
    g_rules.clear();
    FILE *f = fopen(SENTINEL_RULES, "r");
    if (!f) return;
    char line[1024];
    while (fgets(line, sizeof(line), f)) {
        line[strcspn(line, "\n")] = 0;
        if (line[0] == '#' || line[0] == 0) continue;
        char verb[8], sha[80]; int pos = 0;
        // %n records where parsing stopped, so we pick up the path right after the
        // verb+sha fields instead of re-finding the sha by substring (which could
        // match the wrong spot — e.g. a path-only "-" rule whose path contains a
        // dash).
        if (sscanf(line, "%7s %79s %n", verb, sha, &pos) < 2 || pos == 0) continue;
        char *exe = line + pos;
        while (*exe == ' ') ++exe;
        if (!*exe) continue;
        Rule r; r.allow = (strcmp(verb, "allow") == 0);
        r.sha = (strcmp(sha, "-") == 0) ? "" : sha;
        g_rules[exe] = r;
    }
    fclose(f);
}

static void save_rules() {
    run("mkdir -p /etc/sentinel 2>/dev/null");
    FILE *f = fopen(SENTINEL_RULES, "w");
    if (!f) return;
    fprintf(f, "# sentinel rule store — verdict  sha256(exe)  path\n");
    for (auto &kv : g_rules)
        fprintf(f, "%s %s %s\n", kv.second.allow ? "allow" : "deny",
                kv.second.sha.empty() ? "-" : kv.second.sha.c_str(), kv.first.c_str());
    fclose(f);
}

// SHA-256 of an executable, memoised by (size, mtime).
static std::string cached_hex(const std::string &path) {
    struct stat st;
    if (stat(path.c_str(), &st) != 0) return "";
    auto it = g_hash_cache.find(path);
    if (it != g_hash_cache.end() &&
        it->second.mtime == st.st_mtime && it->second.size == st.st_size)
        return it->second.sha;
    std::string h = sha256::file_hex(path);
    g_hash_cache[path] = { st.st_mtime, st.st_size, h };
    return h;
}

// ---------------------------------------------------------------------------
// Process attribution: 5-tuple -> socket inode -> PID -> exe (connmon-derived)
// ---------------------------------------------------------------------------
static unsigned long find_inode(uint16_t local_port, const std::string &dst_ip,
                                uint16_t dst_port, bool v6) {
    const char *path = v6 ? "/proc/net/tcp6" : "/proc/net/tcp";
    FILE *f = fopen(path, "r");
    if (!f) return 0;
    char line[512];
    if (!fgets(line, sizeof(line), f)) { fclose(f); return 0; }  // header
    unsigned long found = 0;
    while (fgets(line, sizeof(line), f)) {
        char lhex[64], rhex[64];
        unsigned lport, rport, st; unsigned long inode = 0;
        if (sscanf(line, "%*d: %63[0-9A-Fa-f]:%x %63[0-9A-Fa-f]:%x %x %*x:%*x %*x:%*x %*x %*u %*d %lu",
                   lhex, &lport, rhex, &rport, &st, &inode) < 6) continue;
        if (lport != local_port || rport != dst_port) continue;
        char rip[INET6_ADDRSTRLEN] = "";
        if (v6) {
            unsigned w[4];
            if (sscanf(rhex, "%8x%8x%8x%8x", &w[0], &w[1], &w[2], &w[3]) == 4) {
                struct in6_addr a; memcpy(&a, w, sizeof(a));
                inet_ntop(AF_INET6, &a, rip, sizeof(rip));
            }
        } else {
            unsigned a; sscanf(rhex, "%x", &a);
            struct in_addr in; in.s_addr = a;
            inet_ntop(AF_INET, &in, rip, sizeof(rip));
        }
        if (dst_ip == rip) { found = inode; break; }
    }
    fclose(f);
    return found;
}

static bool inode_to_proc(unsigned long inode, Conn &c) {
    if (!inode) return false;
    char want[64];
    snprintf(want, sizeof(want), "socket:[%lu]", inode);
    DIR *proc = opendir("/proc");
    if (!proc) return false;
    struct dirent *de;
    bool hit = false;
    while (!hit && (de = readdir(proc))) {
        if (!isdigit((unsigned char)de->d_name[0])) continue;
        int pid = atoi(de->d_name);
        char fdpath[64];
        snprintf(fdpath, sizeof(fdpath), "/proc/%d/fd", pid);
        DIR *fd = opendir(fdpath);
        if (!fd) continue;
        struct dirent *fe;
        while ((fe = readdir(fd))) {
            char link[320], tgt[128];
            snprintf(link, sizeof(link), "/proc/%d/fd/%s", pid, fe->d_name);
            ssize_t n = readlink(link, tgt, sizeof(tgt) - 1);
            if (n < 0) continue;
            tgt[n] = 0;
            if (strcmp(tgt, want) == 0) {
                c.pid = pid;
                char p[64], buf[256];
                snprintf(p, sizeof(p), "/proc/%d/comm", pid);
                FILE *cf = fopen(p, "r");
                if (cf) { if (fgets(buf, sizeof(buf), cf)) { buf[strcspn(buf,"\n")]=0; c.comm = buf; } fclose(cf); }
                snprintf(p, sizeof(p), "/proc/%d/exe", pid);
                ssize_t m = readlink(p, buf, sizeof(buf) - 1);
                if (m > 0) { buf[m] = 0; c.exe = buf; }
                hit = true;
                break;
            }
        }
        closedir(fd);
    }
    closedir(proc);
    return hit;
}

// ---------------------------------------------------------------------------
// GUI socket helpers
// ---------------------------------------------------------------------------
// Write a whole line, looping on short writes so a large posture snapshot is
// never truncated mid-frame. The client socket carries SO_SNDTIMEO, so a wedged
// GUI makes write() fail (EAGAIN) instead of stalling the firewall poll loop
// forever; on any non-EINTR error we just give up and let the loop reap the fd.
static void send_line(int fd, const std::string &s) {
    if (fd < 0) return;
    std::string l = s + "\n";
    size_t off = 0;
    while (off < l.size()) {
        ssize_t w = write(fd, l.data() + off, l.size() - off);
        if (w > 0) { off += (size_t)w; continue; }
        if (w < 0 && errno == EINTR) continue;
        break;   // EAGAIN (send timeout) / EPIPE / other: drop, fd is reaped later
    }
}

static void emit_event(bool allow, const Conn &c, const char *reason) {
    char buf[512];
    snprintf(buf, sizeof(buf), "EVENT\t%s\t%s\t%s\t%u\t%s",
             allow ? "allow" : "deny", c.exe.c_str(), c.dst_ip.c_str(), c.dst_port, reason);
    send_line(g_client_fd, buf);
}

// Push one line into the Posture page's live "Changes" feed. Shared by the
// scan-diff path (no detail) and the two continuous watchers below (with
// detail) — see the PALERT description in sentinel_proto.h.
static void send_alert(int sev, const std::string &cat, const std::string &title,
                        const std::string &detail = "") {
    std::string line = "PALERT\t" + std::to_string(sev) + "\t" +
                        sentinel_b64::encode(cat) + "\t" +
                        sentinel_b64::encode(title) + "\t" +
                        sentinel_b64::encode(detail);
    send_line(g_client_fd, line);
}

static long now_ms() {
    struct timespec ts; clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000L + ts.tv_nsec / 1000000L;
}

static void finish(uint32_t ask_id, bool allow, bool forever, const char *reason) {
    auto it = g_pending.find(ask_id);
    if (it == g_pending.end()) return;
    Pending p = it->second;
    g_pending.erase(it);

    if (forever && p.conn.exe != "?") {
        Rule r; r.allow = allow;
        r.sha = allow ? cached_hex(p.conn.exe) : "";
        g_rules[p.conn.exe] = r; save_rules();
    }
    emit_event(allow, p.conn, reason);
    nfq_set_verdict(g_qh, p.pkt_id, allow ? NF_ACCEPT : NF_DROP, 0, nullptr);
}

static void check_timeouts() {
    if (g_pending.empty()) return;
    long t = now_ms();
    std::vector<uint32_t> expired;
    for (auto &kv : g_pending)
        if (kv.second.deadline_ms <= t) expired.push_back(kv.first);
    for (uint32_t id : expired)
        finish(id, SENTINEL_DEFAULT_NO_UI_ACCEPT, false, "timeout-default");
}

static void resolve_all_pending(const char *reason) {
    std::vector<uint32_t> ids;
    for (auto &kv : g_pending) ids.push_back(kv.first);
    for (uint32_t id : ids) finish(id, SENTINEL_DEFAULT_NO_UI_ACCEPT, false, reason);
}

// ---------------------------------------------------------------------------
// Posture scanning
// ---------------------------------------------------------------------------

// Worker thread body: run the (potentially slow) scan, then publish the result.
static void posture_worker() {
    ScanReport *r = scan_run(nullptr, nullptr);   // documented thread-safe
    std::lock_guard<std::mutex> lk(g_scan_mtx);
    if (g_scan_ready) scan_report_free(g_scan_ready);  // drop an un-collected one
    g_scan_ready = r;
}

static void kick_scan_if_due(bool force) {
    if (g_scan_inflight.load()) return;
    long t = now_ms();
    if (!force && g_last_scan_ms >= 0 && (t - g_last_scan_ms) < g_scan_interval_ms)
        return;
    g_last_scan_ms = t;
    g_scan_inflight.store(true);
    std::thread(posture_worker).detach();
}

static std::string b64(const char *s) {
    return sentinel_b64::encode(s ? s : "");
}

// Build the framed snapshot (PBEGIN .. PFINDING* .. PEND) for a report.
static std::string frame_snapshot(const ScanReport *r) {
    std::string out;
    char hdr[256];
    snprintf(hdr, sizeof(hdr), "PBEGIN\t%s\t%d\t%d\t%d\t%d\t%d\n",
             b64(r->scanned_at).c_str(), r->counts[0], r->counts[1],
             r->counts[2], r->counts[3], r->counts[4]);
    out += hdr;
    for (guint i = 0; i < r->items->len; i++) {
        const Finding *f = (const Finding *)g_ptr_array_index(r->items, i);
        out += "PFINDING\t";
        out += std::to_string((int)f->severity); out += '\t';
        out += b64(f->category);    out += '\t';
        out += b64(f->title);       out += '\t';
        out += b64(f->detail);      out += '\t';
        out += b64(f->suggestion);  out += '\t';
        out += b64(f->fix_command); out += '\n';
    }
    out += "PEND\n";
    return out;
}

// Diff a freshly-finished report against the previous one and emit change
// alerts for newly-appeared or worsened problems (and "cleared" notes when a
// problem goes away). This is the heart of the real-time posture monitor.
static void diff_and_emit_alerts(const ScanReport *r) {
    std::map<std::string,int> cur;
    for (guint i = 0; i < r->items->len; i++) {
        const Finding *f = (const Finding *)g_ptr_array_index(r->items, i);
        std::string key = std::string(f->category ? f->category : "") + "\x1f" +
                          std::string(f->title ? f->title : "");
        // Keep the most severe instance if a title repeats.
        auto it = cur.find(key);
        if (it == cur.end() || f->severity > it->second) cur[key] = f->severity;
    }

    auto title_of = [](const std::string &key) {
        size_t p = key.find('\x1f');
        return p == std::string::npos ? key : key.substr(p + 1);
    };
    auto cat_of = [](const std::string &key) {
        size_t p = key.find('\x1f');
        return p == std::string::npos ? std::string() : key.substr(0, p);
    };
    auto alert = [&](int sev, const std::string &key) {
        send_alert(sev, cat_of(key), title_of(key));
    };

    if (g_have_prev) {
        // New or worsened "bad" findings (>= MEDIUM) are what the user cares about.
        for (auto &kv : cur) {
            auto p = g_prev_sev.find(kv.first);
            bool isnew = (p == g_prev_sev.end());
            bool worse = (!isnew && kv.second > p->second);
            if ((isnew && kv.second >= SEV_MEDIUM) ||
                (worse && kv.second >= SEV_MEDIUM))
                alert(kv.second, kv.first);
        }
        // A previously-bad finding that dropped to OK or vanished: a "cleared" note.
        for (auto &kv : g_prev_sev) {
            if (kv.second < SEV_MEDIUM) continue;
            auto c = cur.find(kv.first);
            if (c == cur.end() || c->second < SEV_MEDIUM)
                alert(SEV_OK, kv.first);   // sev 0 == resolved
        }
    }

    g_prev_sev = std::move(cur);
    g_have_prev = true;
}

// Called each main-loop tick: if a worker finished, frame + diff + send.
static void collect_finished_scan() {
    ScanReport *r = nullptr;
    {
        std::lock_guard<std::mutex> lk(g_scan_mtx);
        if (g_scan_ready) { r = g_scan_ready; g_scan_ready = nullptr; }
    }
    if (!r) return;
    g_scan_inflight.store(false);

    g_last_snapshot = frame_snapshot(r);   // cache for GUI (re)connects
    if (g_client_fd >= 0) {
        send_line(g_client_fd, g_last_snapshot.substr(0, g_last_snapshot.size() - 1));
        diff_and_emit_alerts(r);
    } else {
        // No GUI watching, but still track state so the first alert after a
        // (re)connect reflects real changes rather than a cold start.
        diff_and_emit_alerts(r);
    }
    scan_report_free(r);
}

// ---------------------------------------------------------------------------
// Live watcher 1: process-exec monitor (kernel proc connector)
//
// Unlike the posture scan (interval-polled), this is push-based: the kernel
// notifies us of every exec() on the box the moment it happens, via a
// NETLINK_CONNECTOR socket subscribed to the proc-event multicast group. We
// flag execs from paths a legitimate install rarely runs from — /tmp,
// /dev/shm, /var/tmp — and execs of an already-unlinked (deleted) binary,
// both classic signs of a dropped or memory-resident payload rather than
// noise from normal package-manager activity.
// ---------------------------------------------------------------------------
static std::unordered_map<std::string, long> g_exec_cooldown;   // exe path -> last alert (ms)
static const long EXEC_COOLDOWN_MS = 10 * 60 * 1000L;            // don't re-alert the same path for 10 min

static int init_exec_watch() {
    int fd = socket(PF_NETLINK, SOCK_DGRAM, NETLINK_CONNECTOR);
    if (fd < 0) {
        fprintf(stderr, "sentinel-daemon: process-exec watch unavailable (%s)\n", strerror(errno));
        return -1;
    }
    struct sockaddr_nl addr;
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_pid    = (uint32_t)getpid();
    addr.nl_groups = CN_IDX_PROC;
    if (bind(fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
        fprintf(stderr, "sentinel-daemon: process-exec watch unavailable (bind: %s)\n", strerror(errno));
        close(fd);
        return -1;
    }

    // cn_msg ends in a flexible array member, so it can't be embedded as a
    // non-last field of another struct (GCC rejects that outright). Build the
    // subscribe message — nlmsghdr + cn_msg + a trailing uint32_t op — as a
    // flat byte buffer instead, the usual idiom for this netlink message.
    size_t msg_len = sizeof(struct nlmsghdr) + sizeof(struct cn_msg) + sizeof(uint32_t);
    std::vector<unsigned char> sub(msg_len, 0);
    struct nlmsghdr *nlh = (struct nlmsghdr *)sub.data();
    nlh->nlmsg_len  = (uint32_t)msg_len;
    nlh->nlmsg_pid  = (uint32_t)getpid();
    nlh->nlmsg_type = NLMSG_DONE;
    struct cn_msg *cn = (struct cn_msg *)NLMSG_DATA(nlh);
    cn->id.idx = CN_IDX_PROC;
    cn->id.val = CN_VAL_PROC;
    cn->len    = sizeof(uint32_t);
    *(uint32_t *)cn->data = PROC_CN_MCAST_LISTEN;
    if (send(fd, sub.data(), msg_len, 0) < 0) {
        fprintf(stderr, "sentinel-daemon: process-exec watch unavailable (subscribe: %s)\n", strerror(errno));
        close(fd);
        return -1;
    }
    return fd;
}

// Paths a normal install almost never executes from directly.
static bool is_suspicious_exec_path(const std::string &exe) {
    if (exe.empty()) return false;
    if (exe.size() > 10 && exe.compare(exe.size() - 10, 10, " (deleted)") == 0)
        return true;   // running a binary already unlinked from disk
    static const char *bad_prefixes[] = {
        "/tmp/", "/var/tmp/", "/dev/shm/", "/run/user/", "/dev/mqueue/",
    };
    for (const char *pre : bad_prefixes)
        if (exe.compare(0, strlen(pre), pre) == 0) return true;
    return false;
}

static void handle_exec_event(pid_t pid) {
    char p[64], exe[512];
    snprintf(p, sizeof(p), "/proc/%d/exe", (int)pid);
    ssize_t n = readlink(p, exe, sizeof(exe) - 1);
    std::string exe_path = (n > 0) ? std::string(exe, n) : std::string();
    if (!is_suspicious_exec_path(exe_path)) return;

    long t = now_ms();
    auto it = g_exec_cooldown.find(exe_path);
    if (it != g_exec_cooldown.end() && (t - it->second) < EXEC_COOLDOWN_MS) return;
    g_exec_cooldown[exe_path] = t;

    std::string comm = "?", ppid = "?";
    snprintf(p, sizeof(p), "/proc/%d/comm", (int)pid);
    FILE *cf = fopen(p, "r");
    if (cf) { char buf[256]; if (fgets(buf, sizeof(buf), cf)) { buf[strcspn(buf, "\n")] = 0; comm = buf; } fclose(cf); }
    snprintf(p, sizeof(p), "/proc/%d/status", (int)pid);
    FILE *sf = fopen(p, "r");
    if (sf) {
        char line[256];
        while (fgets(line, sizeof(line), sf))
            if (strncmp(line, "PPid:", 5) == 0) { ppid = line + 5; ppid.erase(0, ppid.find_first_not_of(" \t"));
                                                   ppid.erase(ppid.find_last_not_of(" \t\n") + 1); break; }
        fclose(sf);
    }

    std::string base = exe_path;
    size_t slash = base.find_last_of('/');
    if (slash != std::string::npos) base = base.substr(slash + 1);
    std::string detail = "exe=" + exe_path + "  pid=" + std::to_string((int)pid) +
                          "  ppid=" + ppid + "  comm=" + comm;
    send_alert(SEV_HIGH, "Process", "Execution from a suspicious path: " + base, detail);
}

// Drain and process pending proc-connector events; non-blocking, called when
// g_exec_fd is readable.
static void drain_exec_watch() {
    char buf[4096];
    for (;;) {
        ssize_t len = recv(g_exec_fd, buf, sizeof(buf), MSG_DONTWAIT);
        if (len <= 0) break;
        struct nlmsghdr *nlh = (struct nlmsghdr *)buf;
        while (NLMSG_OK(nlh, (size_t)len)) {
            if (nlh->nlmsg_type == NLMSG_NOOP) { nlh = NLMSG_NEXT(nlh, len); continue; }
            if (nlh->nlmsg_type == NLMSG_ERROR || nlh->nlmsg_type == NLMSG_DONE) break;
            struct cn_msg *cn = (struct cn_msg *)NLMSG_DATA(nlh);
            struct proc_event *ev = (struct proc_event *)cn->data;
            if (ev->what == PROC_EVENT_EXEC)
                handle_exec_event(ev->event_data.exec.process_pid);
            nlh = NLMSG_NEXT(nlh, len);
        }
    }
}

// ---------------------------------------------------------------------------
// Live watcher 2: auth/login monitor (journalctl tail)
//
// Tails systemd's journal for sshd/sudo/su/useradd/userdel/groupadd/usermod
// entries as they're logged, so a login, a brute-force burst, a sudo
// invocation or a new account shows up the moment it happens — not on the
// next 60s posture re-scan (which only catches *configuration* drift, not
// the fact that someone actually logged in or ran sudo).
// ---------------------------------------------------------------------------
struct FailWindow { std::deque<long> times; long last_alert_ms = -1; };
static std::unordered_map<std::string, FailWindow> g_ssh_fails;   // source ip -> recent failures
static std::unordered_map<std::string, FailWindow> g_su_fails;    // target user -> recent failures
static const long FAIL_WINDOW_MS = 60 * 1000L;
static const int  FAIL_THRESHOLD = 5;

static void init_auth_watch() {
    int fds[2];
    if (pipe(fds) != 0) {
        fprintf(stderr, "sentinel-daemon: auth-log watch unavailable (pipe: %s)\n", strerror(errno));
        return;
    }
    pid_t pid = fork();
    if (pid < 0) {
        fprintf(stderr, "sentinel-daemon: auth-log watch unavailable (fork: %s)\n", strerror(errno));
        close(fds[0]); close(fds[1]);
        return;
    }
    if (pid == 0) {
        // Child: become `journalctl -f`, stdout feeding the pipe; stderr discarded.
        dup2(fds[1], STDOUT_FILENO);
        int devnull = open("/dev/null", O_WRONLY);
        if (devnull >= 0) { dup2(devnull, STDERR_FILENO); close(devnull); }
        close(fds[0]); close(fds[1]);
        execlp("journalctl", "journalctl", "-f", "-n0", "--no-pager", "-o", "short",
               "-t", "sshd", "-t", "sudo", "-t", "su", "-t", "useradd",
               "-t", "userdel", "-t", "groupadd", "-t", "usermod", (char *)nullptr);
        _exit(127);   // no journalctl (non-systemd box) — parent sees EOF and disables the watch
    }
    close(fds[1]);
    g_auth_pid = pid;
    g_auth_fd  = fds[0];
    int fl = fcntl(g_auth_fd, F_GETFL, 0);
    fcntl(g_auth_fd, F_SETFL, fl | O_NONBLOCK);
}

// "... for [invalid user ]<user> from <ip> port <n> ..." (Accepted/Failed lines)
static bool parse_user_ip(const std::string &line, std::string &user, std::string &ip) {
    size_t p = line.find(" for ");
    if (p == std::string::npos) return false;
    p += 5;
    if (line.compare(p, 12, "invalid user") == 0) p += 13;
    size_t sp = line.find(' ', p);
    if (sp == std::string::npos) return false;
    user = line.substr(p, sp - p);
    size_t fp = line.find(" from ", sp);
    if (fp == std::string::npos) return false;
    fp += 6;
    size_t fe = line.find(' ', fp);
    ip = (fe == std::string::npos) ? line.substr(fp) : line.substr(fp, fe - fp);
    return !user.empty() && !ip.empty();
}

static void handle_auth_line(const std::string &line) {
    std::string user, ip;

    if (line.find(" sshd") != std::string::npos || line.find("sshd[") != std::string::npos) {
        if (line.find("Accepted ") != std::string::npos && parse_user_ip(line, user, ip)) {
            int sev = (user == "root") ? SEV_MEDIUM : SEV_LOW;
            send_alert(sev, "Auth", "SSH login: " + user + " from " + ip, line);
            return;
        }
        if (line.find("Failed password") != std::string::npos && parse_user_ip(line, user, ip)) {
            long t = now_ms();
            FailWindow &w = g_ssh_fails[ip];
            w.times.push_back(t);
            while (!w.times.empty() && t - w.times.front() > FAIL_WINDOW_MS) w.times.pop_front();
            if ((int)w.times.size() >= FAIL_THRESHOLD &&
                (w.last_alert_ms < 0 || t - w.last_alert_ms > FAIL_WINDOW_MS)) {
                w.last_alert_ms = t;
                send_alert(SEV_HIGH, "Auth", "Possible SSH brute-force from " + ip,
                           std::to_string(w.times.size()) + " failed logins in the last " +
                           std::to_string(FAIL_WINDOW_MS / 1000) + "s (last user tried: " + user + ")");
            }
            return;
        }
    }
    if (line.find(" su[") != std::string::npos || line.find(" su:") != std::string::npos) {
        if (line.find("FAILED SU") != std::string::npos) {
            std::string target = "?";
            size_t p = line.find("(to ");
            if (p != std::string::npos) {
                p += 4;
                size_t e = line.find(')', p);
                if (e != std::string::npos) target = line.substr(p, e - p);
            }
            long t = now_ms();
            FailWindow &w = g_su_fails[target];
            w.times.push_back(t);
            while (!w.times.empty() && t - w.times.front() > FAIL_WINDOW_MS) w.times.pop_front();
            if ((int)w.times.size() >= FAIL_THRESHOLD &&
                (w.last_alert_ms < 0 || t - w.last_alert_ms > FAIL_WINDOW_MS)) {
                w.last_alert_ms = t;
                send_alert(SEV_HIGH, "Auth", "Possible local su brute-force (target: " + target + ")",
                           std::to_string(w.times.size()) + " failed `su` attempts in the last " +
                           std::to_string(FAIL_WINDOW_MS / 1000) + "s");
            }
            return;
        }
        if (line.find("session opened") != std::string::npos) {
            send_alert(SEV_LOW, "Auth", "su: session opened", line);
            return;
        }
    }
    if (line.find(" sudo:") != std::string::npos) {
        size_t cp = line.find("COMMAND=");
        size_t colon = line.find(" sudo:");
        if (cp != std::string::npos && colon != std::string::npos) {
            size_t us = colon + 6;
            size_t ue = line.find(" : ", us);
            if (ue != std::string::npos) {
                std::string sudo_user = line.substr(us, ue - us);
                sudo_user.erase(0, sudo_user.find_first_not_of(" \t"));
                send_alert(SEV_LOW, "Auth", "sudo: " + sudo_user, line.substr(cp));
            }
        }
        return;
    }
    if (line.find("useradd") != std::string::npos && line.find("new user:") != std::string::npos) {
        send_alert(SEV_HIGH, "Auth", "New user account created", line);
        return;
    }
    if (line.find("groupadd") != std::string::npos && line.find("new group:") != std::string::npos) {
        send_alert(SEV_MEDIUM, "Auth", "New group created", line);
        return;
    }
    if (line.find("userdel") != std::string::npos) {
        send_alert(SEV_MEDIUM, "Auth", "User account removed", line);
        return;
    }
    if (line.find("usermod") != std::string::npos) {
        send_alert(SEV_MEDIUM, "Auth", "User account modified", line);
        return;
    }
}

static void drain_auth_watch() {
    char buf[4096];
    for (;;) {
        ssize_t n = read(g_auth_fd, buf, sizeof(buf));
        if (n > 0) {
            g_auth_rx.append(buf, n);
            size_t nl;
            while ((nl = g_auth_rx.find('\n')) != std::string::npos) {
                std::string line = g_auth_rx.substr(0, nl);
                g_auth_rx.erase(0, nl + 1);
                if (!line.empty()) handle_auth_line(line);
            }
            continue;
        }
        if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK)) break;
        // n == 0 (journalctl exited, e.g. not installed) or a real error: stop watching.
        close(g_auth_fd);
        g_auth_fd = -1;
        // Reap the journalctl child so it doesn't linger as a zombie (SIGCHLD is
        // at its default disposition, so children are not auto-reaped).
        if (g_auth_pid > 0) { waitpid(g_auth_pid, nullptr, 0); g_auth_pid = -1; }
        fprintf(stderr, "sentinel-daemon: auth-log watch ended (journalctl not available?)\n");
        break;
    }
}

// ---------------------------------------------------------------------------
// GUI -> daemon messages
// ---------------------------------------------------------------------------
static void process_client_line(char *line) {
    if (strncmp(line, "VERDICT\t", 8) == 0) {
        uint32_t id; char act[16], scope[16];
        if (sscanf(line + 8, "%u\t%15[^\t]\t%15s", &id, act, scope) == 3)
            finish(id, strcmp(act, "allow") == 0, strcmp(scope, "forever") == 0, "prompt");
    } else if (strncmp(line, "RULE\t", 5) == 0) {
        char *exe = strchr(line + 5, '\t');
        if (exe) { *exe++ = 0; Rule r; r.allow = (strcmp(line + 5, "allow") == 0);
                   r.sha = r.allow ? cached_hex(exe) : ""; g_rules[exe] = r; save_rules(); }
    } else if (strncmp(line, "DELRULE\t", 8) == 0) {
        g_rules.erase(line + 8); save_rules();
    } else if (strncmp(line, "SCANNOW", 7) == 0) {
        kick_scan_if_due(true);
    }
}

static void drain_client(void) {
    char buf[2048];
    ssize_t n = read(g_client_fd, buf, sizeof(buf));
    if (n <= 0) {
        close(g_client_fd); g_client_fd = -1; g_rx.clear();
        resolve_all_pending("gui-gone-default");
        return;
    }
    g_rx.append(buf, n);
    // Control lines from the GUI are tiny; a client that streams megabytes with
    // no newline is misbehaving. Cap the accumulator and drop it rather than
    // letting it grow without bound.
    if (g_rx.size() > (1u << 20)) {
        fprintf(stderr, "sentinel-daemon: client overran receive buffer; dropping it\n");
        close(g_client_fd); g_client_fd = -1; g_rx.clear();
        resolve_all_pending("gui-gone-default");
        return;
    }
    size_t nl;
    while ((nl = g_rx.find('\n')) != std::string::npos) {
        std::string line = g_rx.substr(0, nl);
        g_rx.erase(0, nl + 1);
        if (!line.empty()) process_client_line(&line[0]);
    }
}

// ---------------------------------------------------------------------------
// NFQUEUE callback
// ---------------------------------------------------------------------------
static int decide(struct nfq_q_handle *qh, uint32_t pkt_id, const Conn &c) {
    auto it = g_rules.find(c.exe);
    if (it != g_rules.end()) {
        bool tampered = !it->second.sha.empty() && c.exe != "?" &&
                        it->second.sha != cached_hex(c.exe);
        if (!tampered) {
            emit_event(it->second.allow, c, "rule");
            return nfq_set_verdict(qh, pkt_id, it->second.allow ? NF_ACCEPT : NF_DROP, 0, nullptr);
        }
        emit_event(false, c, "binary-changed");
    }

    if (g_client_fd < 0) {
        bool allow = SENTINEL_DEFAULT_NO_UI_ACCEPT;
        emit_event(allow, c, "no-ui-default");
        return nfq_set_verdict(qh, pkt_id, allow ? NF_ACCEPT : NF_DROP, 0, nullptr);
    }

    uint32_t id = g_next_id++;
    g_pending[id] = { pkt_id, c, now_ms() + SENTINEL_PROMPT_TIMEOUT_MS };
    char ask[640];
    snprintf(ask, sizeof(ask), "ASK\t%u\t%s\t%d\t%s\t%s\t%s\t%u",
             id, c.proto.c_str(), c.pid, c.comm.c_str(), c.exe.c_str(),
             c.dst_ip.c_str(), c.dst_port);
    send_line(g_client_fd, ask);
    return 0;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *, struct nfq_data *nfa, void *) {
    struct nfqnl_msg_packet_hdr *ph = nfq_get_msg_packet_hdr(nfa);
    uint32_t pkt_id = ph ? ntohl(ph->packet_id) : 0;

    unsigned char *payload = nullptr;
    int len = nfq_get_payload(nfa, &payload);
    if (len < 1 || !payload)
        return nfq_set_verdict(qh, pkt_id, NF_ACCEPT, 0, nullptr);

    Conn c;
    int version = payload[0] >> 4;
    uint16_t src_port = 0;
    bool v6 = false;

    if (version == 4 && len >= (int)sizeof(struct iphdr)) {
        struct iphdr *ip = (struct iphdr *)payload;
        if (ip->protocol != IPPROTO_TCP)
            return nfq_set_verdict(qh, pkt_id, NF_ACCEPT, 0, nullptr);
        int ihl = ip->ihl * 4;
        if (len < ihl + (int)sizeof(struct tcphdr))
            return nfq_set_verdict(qh, pkt_id, NF_ACCEPT, 0, nullptr);
        struct tcphdr *tcp = (struct tcphdr *)(payload + ihl);
        src_port    = ntohs(tcp->source);
        c.dst_port  = ntohs(tcp->dest);
        char ip4[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &ip->daddr, ip4, sizeof(ip4));
        c.dst_ip = ip4;
    } else if (version == 6 && len >= (int)sizeof(struct ip6_hdr)) {
        struct ip6_hdr *ip6 = (struct ip6_hdr *)payload;
        if (ip6->ip6_nxt != IPPROTO_TCP)
            return nfq_set_verdict(qh, pkt_id, NF_ACCEPT, 0, nullptr);
        if (len < (int)sizeof(struct ip6_hdr) + (int)sizeof(struct tcphdr))
            return nfq_set_verdict(qh, pkt_id, NF_ACCEPT, 0, nullptr);
        struct tcphdr *tcp = (struct tcphdr *)(payload + sizeof(struct ip6_hdr));
        src_port   = ntohs(tcp->source);
        c.dst_port = ntohs(tcp->dest);
        char ip6s[INET6_ADDRSTRLEN];
        inet_ntop(AF_INET6, &ip6->ip6_dst, ip6s, sizeof(ip6s));
        c.dst_ip = ip6s; v6 = true; c.proto = "tcp6";
    } else {
        return nfq_set_verdict(qh, pkt_id, NF_ACCEPT, 0, nullptr);
    }

    for (int attempt = 0; attempt < 4 && c.pid < 0; ++attempt) {
        if (attempt) usleep(2000);
        unsigned long inode = find_inode(src_port, c.dst_ip, c.dst_port, v6);
        if (inode) inode_to_proc(inode, c);
    }

    return decide(qh, pkt_id, c);
}

// ---------------------------------------------------------------------------
// Unix-socket listener for the GUI
// ---------------------------------------------------------------------------
static int make_listener() {
    unlink(SENTINEL_SOCK);
    int fd = socket(AF_UNIX, SOCK_STREAM, 0);
    if (fd < 0) return -1;
    struct sockaddr_un a; memset(&a, 0, sizeof(a));
    a.sun_family = AF_UNIX;
    strncpy(a.sun_path, SENTINEL_SOCK, sizeof(a.sun_path) - 1);
    if (bind(fd, (struct sockaddr *)&a, sizeof(a)) < 0) { close(fd); return -1; }
    // If the owner UID is pinned (SENTINEL_ALLOW_UID), lock the socket down at the
    // filesystem level too: only that user (and root) can even connect, so a
    // racing local user can't claim control. Without it we fall back to the
    // permissive, world-connectable model gated only by SO_PEERCRED's
    // first-non-root-connector rule in accept_client().
    if (g_owner_uid != (uid_t)-1) {
        if (chown(SENTINEL_SOCK, g_owner_uid, (gid_t)-1) != 0)
            fprintf(stderr, "sentinel-daemon: chown(%s) failed: %s\n",
                    SENTINEL_SOCK, strerror(errno));
        chmod(SENTINEL_SOCK, 0660);
    } else {
        chmod(SENTINEL_SOCK, 0666);
    }
    if (listen(fd, 4) < 0) { close(fd); return -1; }
    return fd;
}

static void accept_client(int lsn) {
    int c = accept(lsn, nullptr, nullptr);
    if (c < 0) return;

    struct ucred cred; socklen_t len = sizeof(cred);
    if (getsockopt(c, SOL_SOCKET, SO_PEERCRED, &cred, &len) != 0) { close(c); return; }

    if (g_owner_uid == (uid_t)-1 && cred.uid != 0)
        g_owner_uid = cred.uid;
    if (cred.uid != 0 && cred.uid != g_owner_uid) {
        fprintf(stderr, "sentinel-daemon: rejected control connection from uid %u\n",
                (unsigned)cred.uid);
        close(c);
        return;
    }

    // A wedged GUI must not block the firewall poll loop on write(); bound every
    // send to a couple of seconds.
    struct timeval tv; tv.tv_sec = 2; tv.tv_usec = 0;
    setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));

    if (g_client_fd >= 0) {
        // A previous GUI is being replaced: release any connections it left held
        // in NFQUEUE so they don't sit stalled until their prompt timeout.
        resolve_all_pending("gui-replaced-default");
        close(g_client_fd);
    }
    g_client_fd = c;
    g_rx.clear();
    send_line(g_client_fd, "HELLO\t" SENTINEL_VERSION);
    // Replay the most recent posture snapshot so a freshly-opened GUI shows the
    // current state without waiting for the next scheduled scan.
    if (!g_last_snapshot.empty())
        send_line(g_client_fd, g_last_snapshot.substr(0, g_last_snapshot.size() - 1));
}

static void on_signal(int) { g_stop = 1; }

int main() {
    if (geteuid() != 0) { fprintf(stderr, "sentinel-daemon must run as root.\n"); return 1; }

    signal(SIGINT, on_signal);
    signal(SIGTERM, on_signal);
    signal(SIGPIPE, SIG_IGN);
    // Leave SIGCHLD at its default. Setting it to SIG_IGN makes the kernel
    // auto-reap every child, which breaks g_spawn_sync() in the posture scanner:
    // its internal waitpid() then fails with ECHILD on every command it runs
    // (flooding the journal and discarding each command's exit status). We reap
    // the one long-lived child we fork ourselves — the journalctl auth-watch —
    // explicitly in drain_auth_watch() and at shutdown instead.
    signal(SIGCHLD, SIG_DFL);

    if (const char *iv = getenv("SENTINEL_SCAN_INTERVAL")) {
        long s = strtol(iv, nullptr, 10);
        if (s >= 5) g_scan_interval_ms = s * 1000L;   // floor at 5s to stay sane
    }

    load_rules();
    install_nft();

    struct nfq_handle *h = nfq_open();
    if (!h) { fprintf(stderr, "nfq_open failed\n"); remove_nft(); return 1; }
    nfq_unbind_pf(h, AF_INET);
    nfq_bind_pf(h, AF_INET);
    nfq_bind_pf(h, AF_INET6);
    struct nfq_q_handle *qh = nfq_create_queue(h, SENTINEL_QUEUE_NUM, &cb, nullptr);
    if (!qh) { fprintf(stderr, "nfq_create_queue failed (queue %d busy?)\n", SENTINEL_QUEUE_NUM);
               nfq_close(h); remove_nft(); return 1; }
    nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff);
    g_qh = qh;

    if (const char *env = getenv("SENTINEL_ALLOW_UID"))
        g_owner_uid = (uid_t)strtoul(env, nullptr, 10);

    int qfd = nfq_fd(h);

    // Under load NFQUEUE can overrun the netlink receive buffer; asking the kernel
    // not to deliver ENOBUFS keeps the queue flowing instead of dropping us into
    // an error path on every burst.
#ifdef NETLINK_NO_ENOBUFS
    { int one = 1; setsockopt(qfd, SOL_NETLINK, NETLINK_NO_ENOBUFS, &one, sizeof(one)); }
#endif

    int lsn = make_listener();
    if (lsn < 0) {
        // Without the control socket no GUI can ever attach, so every new
        // connection would silently hit the fail-open default — the firewall
        // would appear up while enforcing nothing. Refuse to run in that state.
        fprintf(stderr, "sentinel-daemon: could not create %s; refusing to run "
                "with the firewall effectively disabled\n", SENTINEL_SOCK);
        nfq_destroy_queue(qh); nfq_close(h); remove_nft();
        return 1;
    }

    if (!getenv("SENTINEL_DISABLE_EXEC_WATCH"))
        g_exec_fd = init_exec_watch();
    if (!getenv("SENTINEL_DISABLE_AUTH_WATCH"))
        init_auth_watch();

    fprintf(stderr, "sentinel-daemon %s up — queue %d, socket %s, scan every %lds, "
            "exec-watch %s, auth-watch %s\n",
            SENTINEL_VERSION, SENTINEL_QUEUE_NUM, SENTINEL_SOCK, g_scan_interval_ms / 1000,
            g_exec_fd >= 0 ? "on" : "off", g_auth_fd >= 0 ? "on" : "off");

    kick_scan_if_due(true);   // first posture scan right away

    char pktbuf[0x10000] __attribute__((aligned));
    while (!g_stop) {
        struct pollfd fds[5];
        int n = 0;
        fds[n].fd = qfd;  fds[n].events = POLLIN; n++;
        if (lsn >= 0)         { fds[n].fd = lsn;         fds[n].events = POLLIN; n++; }
        if (g_client_fd >= 0) { fds[n].fd = g_client_fd; fds[n].events = POLLIN; n++; }
        if (g_exec_fd >= 0)   { fds[n].fd = g_exec_fd;   fds[n].events = POLLIN; n++; }
        if (g_auth_fd >= 0)   { fds[n].fd = g_auth_fd;   fds[n].events = POLLIN; n++; }

        if (poll(fds, n, 1000) < 0) { if (errno == EINTR) continue; break; }

        int client_fd_snapshot = g_client_fd;
        for (int i = 0; i < n; ++i) {
            if (!(fds[i].revents & POLLIN)) continue;
            if (fds[i].fd == qfd) {
                int r = recv(qfd, pktbuf, sizeof(pktbuf), 0);
                if (r >= 0) nfq_handle_packet(h, pktbuf, r);
            } else if (fds[i].fd == lsn) {
                accept_client(lsn);
            } else if (fds[i].fd == client_fd_snapshot && g_client_fd == client_fd_snapshot) {
                drain_client();
            } else if (fds[i].fd == g_exec_fd) {
                drain_exec_watch();
            } else if (fds[i].fd == g_auth_fd) {
                drain_auth_watch();
            }
        }

        check_timeouts();          // release any firewall prompts the user ignored
        collect_finished_scan();   // publish a finished posture scan, if any
        kick_scan_if_due(false);   // start the next posture scan when due
    }

    fprintf(stderr, "\nsentinel-daemon shutting down — removing nftables rules.\n");
    resolve_all_pending("shutdown-default");
    nfq_destroy_queue(qh);
    nfq_close(h);
    remove_nft();
    if (g_client_fd >= 0) close(g_client_fd);
    if (lsn >= 0) close(lsn);
    if (g_exec_fd >= 0) close(g_exec_fd);
    if (g_auth_fd >= 0) close(g_auth_fd);
    if (g_auth_pid > 0) { kill(g_auth_pid, SIGTERM); waitpid(g_auth_pid, nullptr, 0); }
    unlink(SENTINEL_SOCK);
    return 0;
}
