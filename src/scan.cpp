#include "scan.hpp"
#include <glib/gstdio.h>
#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <ctype.h>

/* ------------------------------------------------------------------ */
/* Small helpers                                                       */
/* ------------------------------------------------------------------ */

const char *severity_name(Severity s) {
    switch (s) {
        case SEV_OK:       return "OK";
        case SEV_LOW:      return "LOW";
        case SEV_MEDIUM:   return "MEDIUM";
        case SEV_HIGH:     return "HIGH";
        case SEV_CRITICAL: return "CRITICAL";
    }
    return "?";
}

const char *severity_color(Severity s) {
    switch (s) {
        case SEV_OK:       return "#2e7d32"; /* green  */
        case SEV_LOW:      return "#0277bd"; /* blue   */
        case SEV_MEDIUM:   return "#f9a825"; /* amber  */
        case SEV_HIGH:     return "#e65100"; /* orange */
        case SEV_CRITICAL: return "#c62828"; /* red    */
    }
    return "#000000";
}

static void finding_free(gpointer p) {
    Finding *f = static_cast<Finding *>(p);
    if (!f) return;
    g_free(f->category);
    g_free(f->title);
    g_free(f->detail);
    g_free(f->suggestion);
    g_free(f->fix_command);
    g_free(f);
}

/* Append a finding to the report and bump the severity counter. */
static void add_finding(ScanReport *r, const char *cat, const char *title,
                        Severity sev, const char *detail,
                        const char *suggestion, const char *fix) {
    Finding *f = g_new0(Finding, 1);
    f->category    = g_strdup(cat);
    f->title       = g_strdup(title);
    f->severity    = sev;
    f->detail      = g_strdup(detail ? detail : "");
    f->suggestion  = g_strdup(suggestion ? suggestion : "");
    f->fix_command = fix ? g_strdup(fix) : NULL;
    g_ptr_array_add(r->items, f);
    r->counts[sev]++;
}

/* Run a shell command, return stdout (caller frees). NULL on spawn error. */
static char *run_cmd(const char *cmd) {
    char *out = NULL;
    gint  status = 0;
    GError *err = NULL;
    const char *argv[] = { "/bin/sh", "-c", cmd, NULL };
    if (!g_spawn_sync(NULL, (gchar **)argv, NULL,
                      G_SPAWN_STDERR_TO_DEV_NULL, NULL, NULL,
                      &out, NULL, &status, &err)) {
        if (err) g_error_free(err);
        return NULL;
    }
    return out; /* may be empty string */
}

/* TRUE if a command is found on PATH. */
static gboolean have_cmd(const char *name) {
    char *path = g_find_program_in_path(name);
    gboolean ok = path != NULL;
    g_free(path);
    return ok;
}

static char *chomp_dup(const char *s) {
    if (!s) return g_strdup("");
    char *d = g_strdup(s);
    g_strstrip(d);
    return d;
}

/* ------------------------------------------------------------------ */
/* Individual checks. Each takes the report and appends findings.      */
/* ------------------------------------------------------------------ */

static void check_updates(ScanReport *r) {
    if (have_cmd("apt-get")) {
        char *out = run_cmd("apt-get -s -o Debug::NoLocking=true upgrade 2>/dev/null "
                            "| grep -c '^Inst' ");
        int pending = out ? atoi(out) : 0;
        g_free(out);
        char *sec = run_cmd("apt-get -s -o Debug::NoLocking=true upgrade 2>/dev/null "
                            "| grep -i '^Inst' | grep -ci security");
        int secn = sec ? atoi(sec) : 0;
        g_free(sec);
        if (pending == 0) {
            add_finding(r, "Updates", "System packages up to date", SEV_OK,
                        "No pending package upgrades detected.", "", NULL);
        } else {
            char d[256];
            g_snprintf(d, sizeof d, "%d package(s) can be upgraded, "
                       "%d of which are security updates.", pending, secn);
            add_finding(r, "Updates", "Pending package updates",
                        secn > 0 ? SEV_HIGH : SEV_MEDIUM, d,
                        "Apply outstanding updates, especially security ones. "
                        "Reboot afterwards if the kernel was updated.",
                        "sudo apt-get update && sudo apt-get upgrade -y");
        }
    }
    /* Unattended-upgrades present? */
    if (have_cmd("apt-get")) {
        char *u = run_cmd("dpkg -l unattended-upgrades 2>/dev/null | grep -c '^ii'");
        int has = u ? atoi(u) : 0;
        g_free(u);
        if (!has) {
            add_finding(r, "Updates", "Automatic security updates not installed",
                        SEV_LOW, "The unattended-upgrades package is not installed.",
                        "Install and enable unattended-upgrades so security "
                        "patches are applied automatically.",
                        "sudo apt-get install -y unattended-upgrades && "
                        "sudo dpkg-reconfigure -plow unattended-upgrades");
        } else {
            add_finding(r, "Updates", "Automatic security updates available",
                        SEV_OK, "unattended-upgrades is installed.", "", NULL);
        }
    }
}

static void check_firewall(ScanReport *r) {
    if (have_cmd("ufw")) {
        /* `ufw status` needs root; capture stderr so we can tell "inactive"
         * apart from "permission denied" and avoid a false HIGH finding. */
        char *out = run_cmd("ufw status 2>&1 | head -1");
        char *s = chomp_dup(out);
        g_free(out);
        if (g_ascii_strcasecmp(s, "") == 0 ||
            g_strstr_len(s, -1, "need to be root") ||
            g_strstr_len(s, -1, "permission") ||
            g_strstr_len(s, -1, "ERROR")) {
            add_finding(r, "Firewall", "Firewall status unknown (needs root)",
                        SEV_LOW, "UFW is installed but its status could not be "
                        "read without root.",
                        "Re-run Envision as root (via pkexec) to verify the "
                        "firewall is active.", NULL);
            g_free(s);
            return;
        }
        if (g_strstr_len(s, -1, "active")) {
            r->firewall_active = TRUE;
            add_finding(r, "Firewall", "UFW firewall is active", SEV_OK,
                        s, "", NULL);
        } else {
            add_finding(r, "Firewall", "Firewall inactive", SEV_HIGH,
                        "UFW is installed but not active.",
                        "Enable a default-deny firewall. Allow only services "
                        "you intentionally expose.",
                        "sudo ufw default deny incoming && "
                        "sudo ufw default allow outgoing && sudo ufw enable");
        }
        g_free(s);
    } else if (have_cmd("firewall-cmd")) {
        char *out = run_cmd("firewall-cmd --state 2>/dev/null");
        char *s = chomp_dup(out); g_free(out);
        gboolean run = g_str_equal(s, "running");
        r->firewall_active = run;
        add_finding(r, "Firewall", run ? "firewalld is running"
                                        : "firewalld not running",
                    run ? SEV_OK : SEV_HIGH,
                    run ? "firewalld reports running." : "firewalld is installed but not running.",
                    run ? "" : "Start and enable firewalld.",
                    run ? NULL : "sudo systemctl enable --now firewalld");
        g_free(s);
    } else {
        add_finding(r, "Firewall", "No host firewall detected", SEV_MEDIUM,
                    "Neither ufw nor firewalld is installed.",
                    "Install a host firewall and enable a default-deny policy.",
                    "sudo apt-get install -y ufw && sudo ufw enable");
    }
}

/* TRUE if a "addr:port" local endpoint is bound to a wildcard (all-interface)
 * address rather than a specific IP or loopback. */
static gboolean endpoint_is_public(const char *local) {
    return g_str_has_prefix(local, "0.0.0.0:") ||
           g_str_has_prefix(local, "*:")       ||
           g_str_has_prefix(local, "[::]:")    ||
           g_str_has_prefix(local, ":::");
}

/* Parse `ss -tulpn` and report publicly-bound endpoints. TCP listeners are
 * treated as genuine exposed services (more serious); UDP sockets are usually
 * a client/browser side-effect (QUIC/HTTP-3, WebRTC, mDNS) so they are noted
 * far more gently. An active host firewall reduces the severity of TCP cases. */
static void check_listening_ports(ScanReport *r) {
    if (!have_cmd("ss")) return;
    char *out = run_cmd("ss -tulpnH 2>/dev/null");
    if (!out) return;
    char **lines = g_strsplit(out, "\n", -1);
    g_free(out);

    GString *tcp_pub = g_string_new(NULL);
    GString *udp_pub = g_string_new(NULL);
    int tcp_count = 0, udp_count = 0;

    for (int i = 0; lines[i]; i++) {
        if (!*lines[i]) continue;
        /* Columns: Netid State Recv-Q Send-Q LocalAddr:Port PeerAddr:Port Process */
        char **col = g_strsplit_set(lines[i], " \t", -1);
        char *tok[16]; int n = 0;
        for (int j = 0; col[j] && n < 16; j++)
            if (*col[j]) tok[n++] = col[j];
        if (n >= 5) {
            const char *netid = tok[0];
            const char *local = tok[4];
            /* Process column only present when we have privilege; guard it. */
            const char *proc  = (n >= 7) ? tok[n-1] : "(process hidden — run as root)";
            if (endpoint_is_public(local)) {
                gboolean is_tcp = g_str_has_prefix(netid, "tcp");
                char *line = g_strdup_printf("  %-4s %-24s %s\n",
                                             netid, local, proc);
                if (is_tcp) { g_string_append(tcp_pub, line); tcp_count++; }
                else        { g_string_append(udp_pub, line); udp_count++; }
                g_free(line);
            }
        }
        g_strfreev(col);
    }
    g_strfreev(lines);

    if (tcp_count == 0 && udp_count == 0) {
        add_finding(r, "Network", "No services bound to public interfaces",
                    SEV_OK, "All listening sockets are bound to localhost "
                    "(127.0.0.1 / ::1) or a specific interface.", "", NULL);
    }

    /* --- TCP listeners: the ones that actually matter --- */
    if (tcp_count > 0) {
        Severity sev = r->firewall_active ? SEV_MEDIUM : SEV_HIGH;
        char d[2048];
        g_snprintf(d, sizeof d,
                   "%d TCP service(s) are LISTENING on all interfaces "
                   "(0.0.0.0 / ::), i.e. reachable from other machines%s:\n%s",
                   tcp_count,
                   r->firewall_active ? " (a host firewall is active, which "
                   "limits who can reach them)" : "",
                   tcp_pub->str);
        add_finding(r, "Network", "TCP services exposed on all interfaces",
                    sev, d,
                    r->firewall_active
                    ? "These are real network services. Your firewall is "
                      "active, so the immediate risk is reduced, but confirm "
                      "each one is meant to be reachable. If a service only "
                      "needs local access, bind it to 127.0.0.1; otherwise make "
                      "sure it is patched and requires authentication."
                    : "A TCP service bound to 0.0.0.0 accepts connections from "
                      "anywhere that can route to this host. Bind it to "
                      "127.0.0.1 if it only needs to be local, and/or enable a "
                      "firewall. Make sure each exposed service is patched and "
                      "authenticated.",
                    "sudo ss -tlpn   # review each listener, then restrict it "
                    "in the app config or firewall");
    }

    /* --- UDP sockets: almost always benign client-side traffic --- */
    if (udp_count > 0) {
        char d[2048];
        g_snprintf(d, sizeof d,
                   "%d UDP socket(s) are bound to all interfaces "
                   "(0.0.0.0 / ::). NOTE: this is usually NOT a security "
                   "problem — web browsers, media apps and system services open "
                   "outbound UDP ports for QUIC/HTTP-3, WebRTC and mDNS, and the "
                   "port number is random and changes each run:\n%s",
                   udp_count, udp_pub->str);
        add_finding(r, "Network", "UDP sockets bound to all interfaces (usually benign)",
                    SEV_LOW, d,
                    "Unlike TCP, a UDP socket here is normally a client (e.g. a "
                    "browser doing QUIC/HTTP-3 or a video call), not a server "
                    "waiting for inbound connections. Only investigate if you "
                    "recognise a server process you did not intend to expose. "
                    "Closing the application removes the socket.",
                    NULL);
    }

    g_string_free(tcp_pub, TRUE);
    g_string_free(udp_pub, TRUE);
}

static void check_ssh(ScanReport *r) {
    if (!g_file_test("/etc/ssh/sshd_config", G_FILE_TEST_EXISTS)) {
        add_finding(r, "SSH", "OpenSSH server not configured", SEV_OK,
                    "No /etc/ssh/sshd_config present; SSH server likely not "
                    "installed.", "", NULL);
        return;
    }
    char *cfg = run_cmd("sshd -T 2>/dev/null || cat /etc/ssh/sshd_config");
    if (!cfg) return;
    char *low = g_ascii_strdown(cfg, -1);
    g_free(cfg);

    if (g_strstr_len(low, -1, "permitrootlogin yes")) {
        add_finding(r, "SSH", "Root SSH login permitted", SEV_HIGH,
                    "PermitRootLogin is set to yes.",
                    "Disable direct root login over SSH; log in as a normal "
                    "user and escalate with sudo.",
                    "sudo sed -i 's/^#\\?PermitRootLogin.*/PermitRootLogin no/' "
                    "/etc/ssh/sshd_config && sudo systemctl restart ssh");
    }
    if (g_strstr_len(low, -1, "passwordauthentication yes")) {
        add_finding(r, "SSH", "SSH password authentication enabled", SEV_MEDIUM,
                    "PasswordAuthentication is enabled.",
                    "Prefer key-based authentication and disable passwords to "
                    "defeat brute-force and credential-stuffing.",
                    "sudo sed -i 's/^#\\?PasswordAuthentication.*/PasswordAuthentication no/' "
                    "/etc/ssh/sshd_config && sudo systemctl restart ssh");
    }
    if (g_strstr_len(low, -1, "permitemptypasswords yes")) {
        add_finding(r, "SSH", "SSH permits empty passwords", SEV_CRITICAL,
                    "PermitEmptyPasswords is enabled — an account with a blank "
                    "password could be logged into over the network.",
                    "Never allow empty-password SSH logins.",
                    "sudo sed -i 's/^#\\?PermitEmptyPasswords.*/PermitEmptyPasswords no/' "
                    "/etc/ssh/sshd_config && sudo systemctl restart ssh");
    }
    if (g_strstr_len(low, -1, "x11forwarding yes")) {
        add_finding(r, "SSH", "SSH X11 forwarding enabled", SEV_LOW,
                    "X11Forwarding is enabled.",
                    "Disable X11 forwarding unless you genuinely need it; it widens "
                    "the trust boundary between the server and connecting clients.",
                    "sudo sed -i 's/^#\\?X11Forwarding.*/X11Forwarding no/' "
                    "/etc/ssh/sshd_config && sudo systemctl restart ssh");
    }
    g_free(low);
}

static void check_sudoers(ScanReport *r) {
    if (g_access("/etc/sudoers", R_OK) != 0) {
        add_finding(r, "Privileges", "Sudo rule check skipped (needs root)",
                    SEV_LOW, "/etc/sudoers is not readable without root, so "
                    "passwordless-sudo rules could not be checked.",
                    "Re-run Envision as root (via pkexec) for the full check.",
                    NULL);
        return;
    }
    char *out = run_cmd("grep -rhE '^[^#]*NOPASSWD' /etc/sudoers /etc/sudoers.d 2>/dev/null");
    char *s = chomp_dup(out); g_free(out);
    if (s && *s) {
        add_finding(r, "Privileges", "Passwordless sudo (NOPASSWD) configured",
                    SEV_HIGH, s,
                    "A NOPASSWD sudo rule lets this user — and anything running "
                    "as them, including a compromised app — become root without "
                    "re-entering a password. This is sometimes set intentionally "
                    "for convenience on a single-user machine; if so, understand "
                    "that it removes a key barrier to privilege escalation. The "
                    "safer setup is to scope NOPASSWD to a specific command, or "
                    "remove it and accept the occasional password prompt.",
                    "sudo visudo   # remove or narrow the NOPASSWD rule");
    } else {
        add_finding(r, "Privileges", "No passwordless sudo rules", SEV_OK,
                    "No NOPASSWD entries found in sudoers.", "", NULL);
    }
    g_free(s);
}

static void check_accounts(ScanReport *r) {
    /* Non-root UID 0 accounts. */
    char *uid0 = run_cmd("awk -F: '($3==0){print $1}' /etc/passwd | grep -v '^root$'");
    char *u = chomp_dup(uid0); g_free(uid0);
    if (u && *u) {
        add_finding(r, "Accounts", "Extra UID 0 (root-equivalent) account",
                    SEV_CRITICAL, u,
                    "Accounts other than root with UID 0 have full root power. "
                    "Investigate and remove unless intentional.",
                    "sudo passwd -l <user>   # and review /etc/passwd");
    }
    g_free(u);

    /* Empty password fields. Reading /etc/shadow needs root; never shell out to
     * sudo here — in a GUI with no terminal that would hang waiting for input. */
    if (g_access("/etc/shadow", R_OK) != 0) {
        add_finding(r, "Accounts", "Empty-password check skipped (needs root)",
                    SEV_LOW, "/etc/shadow is not readable, so accounts with "
                    "empty passwords could not be checked.",
                    "Re-run Envision as root (via pkexec) for the full account "
                    "audit.", NULL);
    } else {
        char *empty = run_cmd("awk -F: '($2==\"\"){print $1}' /etc/shadow 2>/dev/null");
        char *e = chomp_dup(empty); g_free(empty);
        if (e && *e) {
            add_finding(r, "Accounts", "Account(s) with empty password",
                        SEV_CRITICAL, e,
                        "These accounts can be logged into with no password at "
                        "all. Lock the account or set a password immediately.",
                        "sudo passwd -l <user>");
        } else {
            add_finding(r, "Accounts", "No accounts with empty passwords", SEV_OK,
                        "Every account in /etc/shadow has a password set or is "
                        "locked.", "", NULL);
        }
        g_free(e);
    }
}

static void check_world_writable(ScanReport *r) {
    /* World-writable files in sensitive dirs, excluding sticky-bit dirs. */
    char *out = run_cmd("find /etc /usr/bin /usr/sbin /bin /sbin -xdev -type f "
                        "-perm -0002 2>/dev/null | head -20");
    char *s = chomp_dup(out); g_free(out);
    if (s && *s) {
        add_finding(r, "Filesystem", "World-writable files in system dirs",
                    SEV_HIGH, s,
                    "Any user can modify these files. Remove the world-writable "
                    "bit.", "sudo chmod o-w <file>");
    } else {
        add_finding(r, "Filesystem", "No world-writable system files", SEV_OK,
                    "No world-writable files found in core system directories.",
                    "", NULL);
    }
    g_free(s);
}

static void check_suid(ScanReport *r) {
    /* Unexpected SUID binaries: report the full list for review. */
    char *out = run_cmd("find / -xdev -perm -4000 -type f 2>/dev/null | head -40");
    char *s = chomp_dup(out); g_free(out);
    int count = 0;
    if (s && *s) for (char *p = s; *p; p++) if (*p == '\n') count++;
    char d[4096];
    g_snprintf(d, sizeof d,
               "%d SUID binaries found (this is informational — a typical "
               "Linux system has 15-30, and most below are standard system "
               "tools like sudo, passwd, mount and su):\n%s",
               s && *s ? count + 1 : 0, s ? s : "");
    add_finding(r, "Filesystem", "SUID binaries inventory (informational)", SEV_LOW, d,
                "SUID binaries run with their owner's privileges (often root). "
                "Having them is normal and expected. Only act if you spot a "
                "binary you do not recognise or that was added by a non-standard "
                "package — those are worth investigating. There is nothing to "
                "fix here by default.",
                "sudo chmod u-s <binary>   # ONLY for an unexpected binary you "
                "have confirmed does not need SUID");
    g_free(s);
}

static void check_kernel_hardening(ScanReport *r) {
    /* "atleast" = TRUE means any value >= want is acceptable (so a stricter
     * setting such as kptr_restrict=2 or rp_filter=2 is not flagged). */
    struct { const char *key; const char *want; gboolean atleast; const char *why; const char *sev_detail; Severity sev; } params[] = {
        { "kernel.randomize_va_space", "2", FALSE,
          "ASLR should be set to 2 (full randomization).", "ASLR", SEV_HIGH },
        { "net.ipv4.conf.all.rp_filter", "1", TRUE,
          "Reverse-path filtering helps block spoofed packets (1=strict, 2=loose).", "rp_filter", SEV_LOW },
        { "net.ipv4.tcp_syncookies", "1", TRUE,
          "SYN cookies mitigate SYN-flood denial of service.", "syncookies", SEV_LOW },
        { "net.ipv4.conf.all.accept_redirects", "0", FALSE,
          "ICMP redirects should not be accepted on a host.", "accept_redirects", SEV_LOW },
        { "kernel.kptr_restrict", "1", TRUE,
          "Restricting kernel pointer exposure hampers exploit development.", "kptr_restrict", SEV_LOW },
    };
    for (size_t i = 0; i < G_N_ELEMENTS(params); i++) {
        char cmd[128];
        g_snprintf(cmd, sizeof cmd, "sysctl -n %s 2>/dev/null", params[i].key);
        char *out = run_cmd(cmd);
        char *v = chomp_dup(out); g_free(out);
        if (!v || !*v) { g_free(v); continue; } /* key not present on this kernel */
        gboolean ok = params[i].atleast ? (atoi(v) >= atoi(params[i].want))
                                         : g_str_equal(v, params[i].want);
        if (!ok) {
            char d[256], fix[256], title[128];
            g_snprintf(title, sizeof title, "Kernel param %s = %s (want %s)",
                       params[i].sev_detail, v, params[i].want);
            g_snprintf(d, sizeof d, "%s is %s; recommended %s. %s",
                       params[i].key, v, params[i].want, params[i].why);
            g_snprintf(fix, sizeof fix,
                       "echo '%s = %s' | sudo tee /etc/sysctl.d/99-envision.conf "
                       "&& sudo sysctl --system", params[i].key, params[i].want);
            add_finding(r, "Kernel", title, params[i].sev, d, params[i].why, fix);
        }
        g_free(v);
    }
}

static void check_disk_encryption(ScanReport *r) {
    char *out = run_cmd("lsblk -o TYPE 2>/dev/null | grep -c crypt");
    int crypt = out ? atoi(out) : 0;
    g_free(out);
    if (crypt > 0) {
        add_finding(r, "Storage", "Disk encryption in use", SEV_OK,
                    "At least one LUKS/crypt device is present.", "", NULL);
    } else {
        add_finding(r, "Storage", "No disk encryption detected", SEV_MEDIUM,
                    "No LUKS/dm-crypt devices were found.",
                    "Full-disk encryption protects data at rest if the machine "
                    "is lost or stolen. It generally must be enabled at install "
                    "time; plan a reinstall or use encrypted home directories.",
                    NULL);
    }
}

static void check_aslr_services(ScanReport *r) {
    /* Failed systemd units can indicate a misconfigured / abandoned service. */
    if (!have_cmd("systemctl")) return;
    char *out = run_cmd("systemctl list-units --failed --no-legend --plain "
                        "2>/dev/null | awk '{print $1}' | grep -v '^$'");
    char *s = chomp_dup(out); g_free(out);
    if (s && *s) {
        add_finding(r, "Services", "Failed systemd units", SEV_LOW, s,
                    "Failed units may be misconfigured or abandoned services. "
                    "Review and either fix or disable them.",
                    "systemctl status <unit>");
    }
    g_free(s);
}

static void check_coredumps(ScanReport *r) {
    char *out = run_cmd("sysctl -n fs.suid_dumpable 2>/dev/null");
    char *v = chomp_dup(out); g_free(out);
    if (v && g_str_equal(v, "1")) {
        add_finding(r, "Kernel", "SUID core dumps enabled", SEV_MEDIUM,
                    "fs.suid_dumpable = 1 allows SUID programs to dump core, "
                    "potentially leaking sensitive memory.",
                    "Set fs.suid_dumpable to 0.",
                    "echo 'fs.suid_dumpable = 0' | sudo tee "
                    "/etc/sysctl.d/99-envision-coredump.conf && sudo sysctl --system");
    }
    g_free(v);
}

/* Mandatory Access Control: AppArmor or SELinux in enforcing mode confines
 * services so a compromised process cannot freely touch the rest of the system. */
static void check_mac(ScanReport *r) {
    /* SELinux first (Fedora/RHEL/CentOS). */
    if (g_file_test("/sys/fs/selinux/enforce", G_FILE_TEST_EXISTS) ||
        have_cmd("getenforce")) {
        char *out = run_cmd("getenforce 2>/dev/null");
        char *s = chomp_dup(out); g_free(out);
        if (g_ascii_strcasecmp(s, "Enforcing") == 0) {
            add_finding(r, "Hardening", "SELinux is enforcing", SEV_OK,
                        "SELinux is in enforcing mode.", "", NULL);
        } else if (g_ascii_strcasecmp(s, "Permissive") == 0) {
            add_finding(r, "Hardening", "SELinux is only permissive", SEV_MEDIUM,
                        "SELinux is loaded but in permissive mode: it logs "
                        "violations but does not block them.",
                        "Switch SELinux to enforcing once you have confirmed no "
                        "legitimate service is being denied.",
                        "sudo setenforce 1 && sudo sed -i "
                        "'s/^SELINUX=.*/SELINUX=enforcing/' /etc/selinux/config");
        } else if (g_ascii_strcasecmp(s, "Disabled") == 0) {
            add_finding(r, "Hardening", "SELinux is disabled", SEV_MEDIUM,
                        "SELinux is present but disabled.",
                        "Enable SELinux in enforcing mode for defence-in-depth "
                        "confinement of services.",
                        "sudo sed -i 's/^SELINUX=.*/SELINUX=enforcing/' "
                        "/etc/selinux/config   # then reboot");
        }
        g_free(s);
        return;
    }
    /* AppArmor (Debian/Ubuntu/SUSE). */
    if (have_cmd("aa-status") || g_file_test("/sys/module/apparmor",
                                             G_FILE_TEST_IS_DIR)) {
        char *out = run_cmd("aa-status --enabled 2>/dev/null; echo $?");
        char *s = chomp_dup(out); g_free(out);
        gboolean enabled = (s && g_str_has_suffix(s, "0"));
        g_free(s);
        if (enabled) {
            char *prof = run_cmd("aa-status 2>/dev/null | "
                                 "grep -oE '[0-9]+ profiles are in enforce' "
                                 "| grep -oE '^[0-9]+'");
            char *p = chomp_dup(prof); g_free(prof);
            char d[160];
            g_snprintf(d, sizeof d, "AppArmor is enabled%s%s.",
                       (p && *p) ? " with " : "", (p && *p) ? p : "");
            add_finding(r, "Hardening", "AppArmor is enabled", SEV_OK, d, "", NULL);
            g_free(p);
        } else {
            add_finding(r, "Hardening", "AppArmor present but not enabled",
                        SEV_MEDIUM, "The AppArmor module is available but no "
                        "profiles are being enforced.",
                        "Enable AppArmor so packaged service profiles confine "
                        "daemons such as the browser, CUPS and MySQL.",
                        "sudo systemctl enable --now apparmor");
        }
        return;
    }
    add_finding(r, "Hardening", "No Mandatory Access Control system", SEV_MEDIUM,
                "Neither SELinux nor AppArmor was detected.",
                "Install a MAC framework (AppArmor on Debian/Ubuntu, SELinux on "
                "RHEL-family) so that a compromised service is confined rather "
                "than able to touch the whole system.",
                "sudo apt-get install -y apparmor apparmor-profiles "
                "&& sudo systemctl enable --now apparmor");
}

/* Brute-force protection: fail2ban (or sshguard) bans IPs after repeated
 * failed logins. Especially important on any host exposing SSH. */
static void check_intrusion_prevention(ScanReport *r) {
    gboolean f2b = have_cmd("fail2ban-client") ||
                   g_file_test("/etc/fail2ban/jail.conf", G_FILE_TEST_EXISTS);
    gboolean sg  = have_cmd("sshguard");
    if (!f2b && !sg) {
        add_finding(r, "Intrusion prevention",
                    "No brute-force protection (fail2ban/sshguard)", SEV_MEDIUM,
                    "Neither fail2ban nor sshguard is installed.",
                    "Install fail2ban to automatically ban hosts that hammer SSH "
                    "or other services with failed logins. This is one of the "
                    "highest-value defences for any internet-facing machine.",
                    "sudo apt-get install -y fail2ban "
                    "&& sudo systemctl enable --now fail2ban");
        return;
    }
    if (f2b) {
        char *out = run_cmd("systemctl is-active fail2ban 2>/dev/null");
        char *s = chomp_dup(out); g_free(out);
        if (g_str_equal(s, "active")) {
            add_finding(r, "Intrusion prevention", "fail2ban is active", SEV_OK,
                        "fail2ban is installed and running.", "", NULL);
        } else {
            add_finding(r, "Intrusion prevention",
                        "fail2ban installed but not running", SEV_MEDIUM,
                        "The fail2ban package is present but the service is not "
                        "active.",
                        "Start and enable fail2ban so its jails actually ban "
                        "abusive hosts.",
                        "sudo systemctl enable --now fail2ban");
        }
        g_free(s);
    } else {
        add_finding(r, "Intrusion prevention", "sshguard present", SEV_OK,
                    "sshguard is installed to throttle brute-force logins.",
                    "", NULL);
    }
}

/* Malware / rootkit tooling: not a real-time scan, just whether the box has any
 * means to detect known malware or rootkits. */
static void check_malware_tools(ScanReport *r) {
    gboolean clam = have_cmd("clamscan") || have_cmd("clamdscan");
    gboolean rk   = have_cmd("rkhunter") || have_cmd("chkrootkit");
    if (clam || rk) {
        char d[160];
        g_snprintf(d, sizeof d, "Detected:%s%s.",
                   clam ? " ClamAV" : "", rk ? " rootkit checker" : "");
        add_finding(r, "Malware", "Malware/rootkit tooling present", SEV_OK,
                    d, "", NULL);
        return;
    }
    add_finding(r, "Malware", "No malware or rootkit scanner installed", SEV_LOW,
                "Neither an antivirus (ClamAV) nor a rootkit checker "
                "(rkhunter/chkrootkit) is installed.",
                "On a server, install rkhunter to baseline the system and detect "
                "known rootkits; on a host that exchanges files with Windows "
                "machines, ClamAV is useful for scanning shared content. Schedule "
                "periodic scans rather than relying on real-time protection.",
                "sudo apt-get install -y rkhunter && sudo rkhunter --propupd "
                "&& sudo rkhunter --check --sk");
}

/* Audit logging: auditd records security-relevant events (logins, privilege
 * use, file access) needed for forensics after an incident. */
static void check_auditd(ScanReport *r) {
    gboolean installed = have_cmd("auditctl") ||
                         g_file_test("/etc/audit/auditd.conf", G_FILE_TEST_EXISTS);
    if (!installed) {
        add_finding(r, "Logging", "Audit daemon (auditd) not installed", SEV_LOW,
                    "The Linux audit framework is not installed.",
                    "On a server, install auditd so that logins, privilege "
                    "escalation and changes to sensitive files are recorded — "
                    "without it there is little forensic trail after a breach.",
                    "sudo apt-get install -y auditd && sudo systemctl enable "
                    "--now auditd");
        return;
    }
    char *out = run_cmd("systemctl is-active auditd 2>/dev/null");
    char *s = chomp_dup(out); g_free(out);
    if (g_str_equal(s, "active"))
        add_finding(r, "Logging", "Audit daemon is running", SEV_OK,
                    "auditd is active and recording security events.", "", NULL);
    else
        add_finding(r, "Logging", "Audit daemon installed but not running",
                    SEV_LOW, "auditd is present but not active.",
                    "Start and enable auditd to retain a security audit trail.",
                    "sudo systemctl enable --now auditd");
    g_free(s);
}

/* Accurate time matters for log correlation, TLS certificate validation,
 * Kerberos/2FA and detecting replay. Check that an NTP client is syncing. */
static void check_time_sync(ScanReport *r) {
    if (have_cmd("timedatectl")) {
        char *out = run_cmd("timedatectl show -p NTPSynchronized --value 2>/dev/null");
        char *s = chomp_dup(out); g_free(out);
        if (g_str_equal(s, "yes")) {
            add_finding(r, "Time", "Clock is synchronised (NTP)", SEV_OK,
                        "The system clock is synchronised to a time source.",
                        "", NULL);
            g_free(s);
            return;
        }
        g_free(s);
        add_finding(r, "Time", "System clock not synchronised", SEV_LOW,
                    "timedatectl reports the clock is not NTP-synchronised.",
                    "Enable network time synchronisation. A drifting clock breaks "
                    "TLS certificate checks, log correlation and time-based "
                    "authentication.",
                    "sudo timedatectl set-ntp true");
        return;
    }
    gboolean any = have_cmd("chronyd") || have_cmd("ntpd") ||
                   g_file_test("/etc/chrony/chrony.conf", G_FILE_TEST_EXISTS);
    if (!any)
        add_finding(r, "Time", "No time-synchronisation client", SEV_LOW,
                    "No NTP client (systemd-timesyncd, chrony or ntpd) was found.",
                    "Install and enable a time client so the clock stays accurate.",
                    "sudo apt-get install -y chrony && sudo systemctl enable "
                    "--now chrony");
}

/* Password aging / strength policy from /etc/login.defs. Weak defaults let a
 * leaked password stay valid forever. */
static void check_password_policy(ScanReport *r) {
    if (!g_file_test("/etc/login.defs", G_FILE_TEST_EXISTS)) return;
    char *out = run_cmd("awk '/^PASS_MAX_DAYS/{print $2}' /etc/login.defs "
                        "2>/dev/null | head -1");
    char *s = chomp_dup(out); g_free(out);
    if (s && *s) {
        int maxd = atoi(s);
        if (maxd <= 0 || maxd > 365) {
            char d[200];
            g_snprintf(d, sizeof d, "PASS_MAX_DAYS is %s; passwords effectively "
                       "never expire.", s);
            add_finding(r, "Accounts", "No password-expiry policy", SEV_LOW, d,
                        "Set a reasonable maximum password age (e.g. 365 days) in "
                        "/etc/login.defs so that long-lived credentials are "
                        "rotated. On a personal single-user laptop this matters "
                        "less; on a multi-user server it is important.",
                        "sudo sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS 365/' "
                        "/etc/login.defs");
        } else {
            add_finding(r, "Accounts", "Password-expiry policy configured",
                        SEV_OK, "PASS_MAX_DAYS is set to a finite value.", "",
                        NULL);
        }
    }
    g_free(s);
    /* Is a password-quality module enforced at all? */
    gboolean pq = g_file_test("/usr/lib/x86_64-linux-gnu/security/pam_pwquality.so",
                              G_FILE_TEST_EXISTS) ||
                  g_file_test("/lib/x86_64-linux-gnu/security/pam_pwquality.so",
                              G_FILE_TEST_EXISTS) ||
                  have_cmd("pwscore");
    if (!pq)
        add_finding(r, "Accounts", "No password-strength enforcement (pwquality)",
                    SEV_LOW, "The pam_pwquality module does not appear to be "
                    "installed, so weak passwords can be set without complaint.",
                    "Install libpam-pwquality to reject trivially weak passwords "
                    "when they are created or changed.",
                    "sudo apt-get install -y libpam-pwquality");
}

/* Automatic login / autologin in the display manager hands a powered-on machine
 * straight to a desktop session with no authentication. */
static void check_autologin(ScanReport *r) {
    char *out = run_cmd(
        "grep -riEl '^[^#]*autologin-user[[:space:]]*=[[:space:]]*[^[:space:]]|"
        "^[^#]*AutomaticLogin[[:space:]]*=[[:space:]]*[^[:space:]]' "
        "/etc/lightdm /etc/gdm3 /etc/gdm /etc/sddm.conf /etc/sddm.conf.d "
        "2>/dev/null");
    char *s = chomp_dup(out); g_free(out);
    if (s && *s) {
        char d[512];
        g_snprintf(d, sizeof d, "Autologin appears to be configured in:\n%s", s);
        add_finding(r, "Login", "Automatic graphical login enabled", SEV_MEDIUM,
                    d,
                    "Autologin means anyone who powers on or reboots this machine "
                    "reaches a full desktop session with no password. Disable it "
                    "unless this is a kiosk or appliance where that is intended; "
                    "combine with full-disk encryption if data matters.",
                    "Edit the listed file(s) and remove the autologin-user / "
                    "AutomaticLogin lines, then reboot.");
    } else {
        add_finding(r, "Login", "No automatic-login configured", SEV_OK,
                    "No display-manager autologin entries were found.", "", NULL);
    }
    g_free(s);
}

/* Scheduled tasks are a classic persistence mechanism. Flag world-writable cron
 * files/dirs, which would let any user alter what runs (often as root). */
static void check_cron(ScanReport *r) {
    char *out = run_cmd("find /etc/crontab /etc/cron.d /etc/cron.daily "
                        "/etc/cron.hourly /etc/cron.weekly /etc/cron.monthly "
                        "/var/spool/cron -perm -0002 2>/dev/null | head -20");
    char *s = chomp_dup(out); g_free(out);
    if (s && *s) {
        add_finding(r, "Scheduled tasks", "World-writable cron files", SEV_HIGH,
                    s,
                    "Any local user can edit these scheduled tasks, which "
                    "typically run as root — a direct path to privilege "
                    "escalation and persistence. Remove the world-writable bit.",
                    "sudo chmod o-w <path>");
    } else {
        add_finding(r, "Scheduled tasks", "Cron files not world-writable", SEV_OK,
                    "No world-writable cron jobs were found.", "", NULL);
    }
    g_free(s);
}

/* An exposed/over-privileged container runtime is effectively root access.
 * Membership of the docker group, or a world-accessible docker socket, both
 * grant trivial host root. */
static void check_docker(ScanReport *r) {
    if (!g_file_test("/var/run/docker.sock", G_FILE_TEST_EXISTS) &&
        !have_cmd("docker"))
        return;
    /* Non-root users in the docker group can escalate to root via `docker run`. */
    char *grp = run_cmd("getent group docker 2>/dev/null | cut -d: -f4");
    char *g = chomp_dup(grp); g_free(grp);
    if (g && *g) {
        char d[256];
        g_snprintf(d, sizeof d, "Members of the docker group: %s", g);
        add_finding(r, "Containers", "Users in docker group (root-equivalent)",
                    SEV_MEDIUM, d,
                    "Anyone in the docker group can mount the host filesystem "
                    "inside a container and become root — it is equivalent to "
                    "passwordless sudo. Only grant it to trusted admins, or use "
                    "rootless Docker / Podman instead.",
                    "sudo gpasswd -d <user> docker   # remove unneeded members");
    }
    g_free(g);
    /* Socket exposed over TCP without TLS is remote root for the network. */
    char *tcp = run_cmd("ss -tlnH 2>/dev/null | grep -E ':2375( |$)'");
    char *t = chomp_dup(tcp); g_free(tcp);
    if (t && *t) {
        add_finding(r, "Containers", "Docker API exposed on TCP 2375 (no TLS)",
                    SEV_CRITICAL, t,
                    "An unauthenticated Docker daemon on port 2375 gives anyone "
                    "who can reach it full root on this host. Disable the TCP "
                    "listener or protect it with mutual TLS on 2376.",
                    "Remove '-H tcp://0.0.0.0:2375' from the docker daemon options "
                    "and restart docker.");
    }
    g_free(t);
}

/* A kernel/library update that requires a reboot leaves the running system on
 * the old, potentially-vulnerable code until it is restarted. */
static void check_reboot_required(ScanReport *r) {
    if (g_file_test("/var/run/reboot-required", G_FILE_TEST_EXISTS) ||
        g_file_test("/run/reboot-required", G_FILE_TEST_EXISTS)) {
        char *who = run_cmd("cat /var/run/reboot-required.pkgs 2>/dev/null "
                            "/run/reboot-required.pkgs 2>/dev/null | sort -u "
                            "| tr '\\n' ' '");
        char *w = chomp_dup(who); g_free(who);
        char d[512];
        g_snprintf(d, sizeof d, "A reboot is required to finish applying "
                   "updates.%s%s", (w && *w) ? " Packages: " : "", (w && *w) ? w : "");
        add_finding(r, "Updates", "Reboot required to apply updates", SEV_MEDIUM,
                    d,
                    "Updated packages (often the kernel or core libraries) only "
                    "take effect after a reboot; until then the old, possibly "
                    "vulnerable code keeps running. Schedule a reboot.",
                    "sudo reboot");
        g_free(w);
        return;
    }
    /* Fallback: compare the running kernel to the newest installed one. */
    char *running = run_cmd("uname -r");
    char *latest  = run_cmd("ls -1 /boot/vmlinuz-* 2>/dev/null | sed "
                            "'s#.*/vmlinuz-##' | sort -V | tail -1");
    char *run = chomp_dup(running); g_free(running);
    char *lat = chomp_dup(latest);  g_free(latest);
    if (run && *run && lat && *lat && !g_str_equal(run, lat)) {
        char d[256];
        g_snprintf(d, sizeof d, "Running kernel %s, but %s is installed.",
                   run, lat);
        add_finding(r, "Updates", "Newer kernel installed but not running",
                    SEV_MEDIUM, d,
                    "A newer kernel is installed but the system is still running "
                    "the old one. Reboot to run the patched kernel.",
                    "sudo reboot");
    }
    g_free(run); g_free(lat);
}

/* UEFI Secure Boot verifies the bootloader/kernel signature and is a baseline
 * defence against boot-level (pre-OS) tampering and bootkits. */
static void check_secure_boot(ScanReport *r) {
    if (!g_file_test("/sys/firmware/efi", G_FILE_TEST_IS_DIR))
        return; /* Legacy BIOS boot — Secure Boot not applicable. */
    char *out = NULL;
    if (have_cmd("mokutil"))
        out = run_cmd("mokutil --sb-state 2>/dev/null");
    if (!out || !*out) {
        g_free(out);
        out = run_cmd("od -An -t u1 "
                      "/sys/firmware/efi/efivars/SecureBoot-* 2>/dev/null "
                      "| awk '{print $NF}'");
    }
    char *s = chomp_dup(out); g_free(out);
    if (!s || !*s) { g_free(s); return; }
    gboolean enabled = g_strstr_len(s, -1, "enabled") || g_str_has_suffix(s, "1");
    if (enabled)
        add_finding(r, "Boot", "UEFI Secure Boot enabled", SEV_OK,
                    "Secure Boot is enabled.", "", NULL);
    else
        add_finding(r, "Boot", "UEFI Secure Boot disabled", SEV_LOW,
                    "The system boots via UEFI but Secure Boot is off.",
                    "Enable Secure Boot in firmware so only signed bootloaders "
                    "and kernels run, reducing the risk of bootkits. Verify your "
                    "distribution supports it before enabling.",
                    "Enable Secure Boot from the UEFI/BIOS setup screen.");
    g_free(s);
}

/* /tmp is world-writable by design; mounting it with noexec/nosuid/nodev (ideally
 * as its own filesystem) blocks a common spot for dropping and running malware. */
static void check_tmp_hardening(ScanReport *r) {
    char *out = run_cmd("findmnt -no OPTIONS /tmp 2>/dev/null");
    char *s = chomp_dup(out); g_free(out);
    if (!s || !*s) {
        g_free(s);
        add_finding(r, "Filesystem", "/tmp is not a separate mount", SEV_LOW,
                    "/tmp is part of the root filesystem rather than its own "
                    "mount, so noexec/nosuid cannot be applied to it.",
                    "Consider a dedicated /tmp (or systemd tmp.mount) with "
                    "noexec,nosuid,nodev so that files dropped in this "
                    "world-writable directory cannot be executed.",
                    NULL);
        return;
    }
    gboolean noexec = g_strstr_len(s, -1, "noexec") != NULL;
    gboolean nosuid = g_strstr_len(s, -1, "nosuid") != NULL;
    if (noexec && nosuid) {
        add_finding(r, "Filesystem", "/tmp mounted with noexec,nosuid", SEV_OK,
                    "/tmp is hardened against executing dropped files.", "", NULL);
    } else {
        add_finding(r, "Filesystem", "/tmp missing noexec/nosuid", SEV_LOW,
                    s,
                    "Add noexec,nosuid,nodev to the /tmp mount so that malware "
                    "dropped into this world-writable directory cannot be run "
                    "directly. /var/tmp and /dev/shm benefit from the same.",
                    "sudo mount -o remount,noexec,nosuid,nodev /tmp   # and update "
                    "/etc/fstab to persist");
    }
    g_free(s);
}

/* Additional kernel-hardening sysctls beyond the core set in
 * check_kernel_hardening(). Individually each is a minor information leak or
 * stack-hardening gap; together they meaningfully shrink local attack surface.
 * Reported LOW so they never drown out the higher-severity findings. */
static void check_kernel_hardening_extra(ScanReport *r) {
    struct { const char *key; const char *want; gboolean atleast; const char *label; const char *why; } params[] = {
        { "kernel.dmesg_restrict", "1", TRUE, "dmesg_restrict",
          "Restricting dmesg keeps kernel addresses/log data away from unprivileged users." },
        { "kernel.yama.ptrace_scope", "1", TRUE, "ptrace_scope",
          "Limiting ptrace stops one of your processes reading another's memory (credential theft)." },
        { "kernel.kexec_load_disabled", "1", TRUE, "kexec_load_disabled",
          "Disabling kexec prevents booting an unverified kernel at runtime, which would bypass Secure Boot." },
        { "kernel.unprivileged_bpf_disabled", "1", TRUE, "unprivileged_bpf_disabled",
          "Blocking unprivileged BPF removes a large and historically buggy kernel attack surface." },
        { "kernel.sysrq", "0", FALSE, "sysrq",
          "The magic SysRq key allows low-level actions from an attached keyboard; disable it unless you rely on it." },
        { "fs.protected_hardlinks", "1", TRUE, "protected_hardlinks",
          "Blocks hardlink-based race attacks in world-writable directories such as /tmp." },
        { "fs.protected_symlinks", "1", TRUE, "protected_symlinks",
          "Blocks symlink-following attacks in world-writable directories such as /tmp." },
        { "net.ipv4.conf.all.send_redirects", "0", FALSE, "send_redirects",
          "A host (non-router) should never send ICMP redirects." },
        { "net.ipv4.conf.all.accept_source_route", "0", FALSE, "accept_source_route",
          "Source-routed packets are a spoofing/route-bypass vector and should be dropped." },
        { "net.ipv4.conf.all.log_martians", "1", TRUE, "log_martians",
          "Logging martian packets records spoofed/impossible source addresses for later investigation." },
    };
    for (size_t i = 0; i < G_N_ELEMENTS(params); i++) {
        char cmd[160];
        g_snprintf(cmd, sizeof cmd, "sysctl -n %s 2>/dev/null", params[i].key);
        char *out = run_cmd(cmd);
        char *v = chomp_dup(out); g_free(out);
        if (!v || !*v) { g_free(v); continue; } /* key not present on this kernel */
        gboolean ok = params[i].atleast ? (atoi(v) >= atoi(params[i].want))
                                        : g_str_equal(v, params[i].want);
        if (!ok) {
            char d[384], fix[256], title[128];
            g_snprintf(title, sizeof title, "Kernel param %s = %s (want %s)",
                       params[i].label, v, params[i].want);
            g_snprintf(d, sizeof d, "%s is %s; recommended %s. %s",
                       params[i].key, v, params[i].want, params[i].why);
            g_snprintf(fix, sizeof fix,
                       "echo '%s = %s' | sudo tee -a /etc/sysctl.d/99-envision.conf "
                       "&& sudo sysctl --system", params[i].key, params[i].want);
            add_finding(r, "Kernel", title, SEV_LOW, d, params[i].why, fix);
        }
        g_free(v);
    }
}

/* A GRUB superuser password stops someone at the console from editing a boot
 * entry (e.g. appending init=/bin/bash) to get a root shell with no login. */
static void check_grub_password(ScanReport *r) {
    if (!g_file_test("/boot/grub/grub.cfg", G_FILE_TEST_EXISTS) &&
        !g_file_test("/boot/grub2/grub.cfg", G_FILE_TEST_EXISTS))
        return; /* not a GRUB system (e.g. systemd-boot) */
    char *out = run_cmd("grep -rhsE '^[[:space:]]*password(_pbkdf2)?[[:space:]]' "
                        "/etc/grub.d /boot/grub/grub.cfg /boot/grub2/grub.cfg "
                        "2>/dev/null");
    char *s = chomp_dup(out); g_free(out);
    if (s && *s) {
        add_finding(r, "Boot", "GRUB bootloader password set", SEV_OK,
                    "A GRUB superuser password is configured.", "", NULL);
    } else {
        add_finding(r, "Boot", "No GRUB bootloader password", SEV_LOW,
                    "GRUB has no superuser password, so anyone at the console can "
                    "edit a boot entry and the kernel command line.",
                    "Set a GRUB password so boot parameters cannot be altered to "
                    "bypass authentication (e.g. booting straight to a root shell). "
                    "Less critical when the disk is encrypted, but still recommended "
                    "for a machine others can physically reach.",
                    "grub-mkpasswd-pbkdf2   # then add 'set superusers' / "
                    "'password_pbkdf2' to /etc/grub.d/40_custom and run "
                    "'sudo update-grub'");
    }
    g_free(s);
}

/* /dev/shm and /var/tmp are world-writable like /tmp and are equally good spots
 * to drop and execute malware, so they deserve the same noexec,nosuid,nodev.
 * (check_tmp_hardening already covers /tmp itself.) */
static void check_extra_mount_hardening(ScanReport *r) {
    const char *mounts[] = { "/dev/shm", "/var/tmp" };
    for (size_t i = 0; i < G_N_ELEMENTS(mounts); i++) {
        char cmd[128];
        g_snprintf(cmd, sizeof cmd, "findmnt -no OPTIONS %s 2>/dev/null", mounts[i]);
        char *out = run_cmd(cmd);
        char *s = chomp_dup(out); g_free(out);
        if (!s || !*s) { g_free(s); continue; } /* not a separate mount */
        gboolean noexec = g_strstr_len(s, -1, "noexec") != NULL;
        gboolean nosuid = g_strstr_len(s, -1, "nosuid") != NULL;
        if (noexec && nosuid) {
            char t[64];
            g_snprintf(t, sizeof t, "%s mounted with noexec,nosuid", mounts[i]);
            add_finding(r, "Filesystem", t, SEV_OK,
                        "Hardened against executing dropped files.", "", NULL);
        } else {
            char t[64], d[256], fix[256];
            g_snprintf(t, sizeof t, "%s missing noexec/nosuid", mounts[i]);
            g_snprintf(d, sizeof d, "%s options: %s", mounts[i], s);
            g_snprintf(fix, sizeof fix,
                       "sudo mount -o remount,noexec,nosuid,nodev %s   # and update "
                       "/etc/fstab to persist", mounts[i]);
            add_finding(r, "Filesystem", t, SEV_LOW, d,
                        "Add noexec,nosuid,nodev to this world-writable mount so "
                        "that malware dropped here cannot be executed directly.",
                        fix);
        }
        g_free(s);
    }
}

/* Loose permissions on the credential/policy files below would let any local
 * user read password hashes or tamper with trusted configuration. */
static void check_sensitive_file_perms(ScanReport *r) {
    struct { const char *path; int max; } files[] = {
        { "/etc/shadow",  0640 }, { "/etc/gshadow", 0640 },
        { "/etc/passwd",  0644 }, { "/etc/group",   0644 },
        { "/etc/sudoers", 0440 },
    };
    GString *bad = g_string_new(NULL);
    for (size_t i = 0; i < G_N_ELEMENTS(files); i++) {
        GStatBuf st;
        if (g_stat(files[i].path, &st) != 0) continue;
        int mode = st.st_mode & 07777;
        /* Any permission bit set beyond the allowed mask is too permissive. */
        if (mode & ~files[i].max)
            g_string_append_printf(bad,
                "  %s is %04o (should be %04o or stricter)\n",
                files[i].path, mode, files[i].max);
    }
    if (bad->len) {
        add_finding(r, "Filesystem",
                    "Over-permissive permissions on sensitive files", SEV_HIGH,
                    bad->str,
                    "These files hold credentials or trusted configuration; loose "
                    "permissions let a local user read password hashes or alter "
                    "policy. Restore the recommended modes.",
                    "sudo chmod 640 /etc/shadow /etc/gshadow && "
                    "sudo chmod 644 /etc/passwd /etc/group && "
                    "sudo chmod 440 /etc/sudoers");
    } else {
        add_finding(r, "Filesystem", "Sensitive file permissions OK", SEV_OK,
                    "Credential and policy files have safe permissions.", "", NULL);
    }
    g_string_free(bad, TRUE);
}

/* Files owned by a UID/GID with no matching account usually remain from a
 * deleted user. They are a tidiness/forensics problem and become a real risk if
 * that numeric ID is later reused — a new user would silently inherit them. */
static void check_unowned_files(ScanReport *r) {
    char *out = run_cmd("find / -xdev \\( -nouser -o -nogroup \\) "
                        "-not -path '/proc/*' 2>/dev/null | head -20");
    char *s = chomp_dup(out); g_free(out);
    if (s && *s) {
        add_finding(r, "Filesystem", "Files with no owner (unowned)", SEV_LOW, s,
                    "These files belong to a user or group that no longer exists. "
                    "Review them and either delete or re-assign ownership; "
                    "otherwise a future account created with the same numeric ID "
                    "would inherit them.",
                    "sudo chown root:root <path>   # or remove if not needed");
    } else {
        add_finding(r, "Filesystem", "No unowned files", SEV_OK,
                    "Every file maps to a valid user and group.", "", NULL);
    }
    g_free(s);
}

/* Locking an account after repeated failed logins slows password guessing.
 * On modern Linux this is pam_faillock (older systems used pam_tally2). */
static void check_account_lockout(ScanReport *r) {
    char *out = run_cmd("grep -rslE 'pam_faillock|pam_tally2?' /etc/pam.d 2>/dev/null");
    char *s = chomp_dup(out); g_free(out);
    if (s && *s) {
        add_finding(r, "Accounts", "Account-lockout policy configured", SEV_OK,
                    "pam_faillock/pam_tally is present in the PAM stack.", "", NULL);
    } else {
        add_finding(r, "Accounts", "No account-lockout policy (pam_faillock)",
                    SEV_LOW,
                    "No PAM module locks an account after repeated failed logins, "
                    "so password guessing is unthrottled.",
                    "Configure pam_faillock so that repeated wrong passwords "
                    "temporarily lock the account. This is most valuable where "
                    "logins are network-reachable (SSH, a display manager).",
                    "sudo pam-auth-update   # enable faillock, then tune "
                    "/etc/security/faillock.conf");
    }
    g_free(s);
}

/* Cleartext / legacy network services (telnet, rsh, FTP, TFTP, NIS, finger)
 * transmit credentials in the clear or have a long history of remote exploits.
 * Their mere presence on a host is worth flagging. */
static void check_legacy_services(ScanReport *r) {
    char *out = run_cmd(
        "dpkg -l 2>/dev/null | awk '/^ii/{print $2}' | sed 's/:.*//' | grep -xE "
        "'(telnetd|telnet-server|inetutils-telnetd|krb5-telnetd|rsh-server|"
        "rsh-redone-server|vsftpd|proftpd-basic|pure-ftpd|tftpd|tftpd-hpa|"
        "atftpd|nis|ypserv|finger|fingerd|talkd|xinetd|openbsd-inetd)' "
        "| tr '\\n' ' '");
    char *s = chomp_dup(out); g_free(out);
    if (s && *s) {
        add_finding(r, "Services", "Legacy/insecure network services installed",
                    SEV_MEDIUM, s,
                    "These services send credentials in cleartext or have a poor "
                    "security history. Remove any you are not deliberately using; "
                    "prefer SSH/SFTP over telnet/rsh/FTP.",
                    "sudo apt-get purge <package>");
    } else {
        add_finding(r, "Services", "No legacy insecure services installed", SEV_OK,
                    "No telnet/rsh/FTP/TFTP/NIS-style packages were found.", "",
                    NULL);
    }
    g_free(s);
}

/* ------------------------------------------------------------------ */
/* Orchestration                                                       */
/* ------------------------------------------------------------------ */

typedef void (*CheckFn)(ScanReport *);

ScanReport *scan_run(ScanProgressFn progress, gpointer user_data) {
    ScanReport *r = g_new0(ScanReport, 1);
    r->items = g_ptr_array_new_with_free_func(finding_free);

    char *h = run_cmd("hostname");           r->hostname  = chomp_dup(h); g_free(h);
    char *o = run_cmd(". /etc/os-release 2>/dev/null; printf '%s' \"$PRETTY_NAME\"");
    r->os_pretty = chomp_dup(o); g_free(o);
    char *k = run_cmd("uname -sr");          r->kernel    = chomp_dup(k); g_free(k);

    time_t now = time(NULL);
    char buf[64];
    strftime(buf, sizeof buf, "%Y-%m-%d %H:%M:%S %Z", localtime(&now));
    r->scanned_at = g_strdup(buf);

    r->is_root = (geteuid() == 0);
    if (!r->is_root)
        add_finding(r, "General", "Scan running without root privileges",
                    SEV_LOW, "Some checks (shadow passwords, sudoers, a full "
                    "filesystem sweep) need root and were limited or skipped.",
                    "For a complete report, launch Envision via pkexec so it "
                    "runs as root.", NULL);

    struct { const char *name; CheckFn fn; } checks[] = {
        { "Updates",   check_updates },
        { "Firewall",  check_firewall },
        { "Network",   check_listening_ports },
        { "SSH",       check_ssh },
        { "Privileges",check_sudoers },
        { "Accounts",  check_accounts },
        { "Filesystem (world-writable)", check_world_writable },
        { "Filesystem (SUID)", check_suid },
        { "Kernel",    check_kernel_hardening },
        { "Kernel (extra)", check_kernel_hardening_extra },
        { "Storage",   check_disk_encryption },
        { "Services",  check_aslr_services },
        { "Core dumps",check_coredumps },
        { "Access control", check_mac },
        { "Intrusion prevention", check_intrusion_prevention },
        { "Account lockout", check_account_lockout },
        { "Malware tooling", check_malware_tools },
        { "Audit logging", check_auditd },
        { "Time sync", check_time_sync },
        { "Password policy", check_password_policy },
        { "Autologin", check_autologin },
        { "Scheduled tasks", check_cron },
        { "Legacy services", check_legacy_services },
        { "Containers", check_docker },
        { "Reboot required", check_reboot_required },
        { "Secure Boot", check_secure_boot },
        { "GRUB password", check_grub_password },
        { "/tmp hardening", check_tmp_hardening },
        { "Mount hardening", check_extra_mount_hardening },
        { "File permissions", check_sensitive_file_perms },
        { "Unowned files", check_unowned_files },
    };
    int total = G_N_ELEMENTS(checks);
    for (int i = 0; i < total; i++) {
        if (progress) progress(checks[i].name, (double)i / total, user_data);
        checks[i].fn(r);
    }
    if (progress) progress("Done", 1.0, user_data);
    return r;
}

void scan_report_free(ScanReport *r) {
    if (!r) return;
    g_ptr_array_free(r->items, TRUE);
    g_free(r->hostname);
    g_free(r->os_pretty);
    g_free(r->kernel);
    g_free(r->scanned_at);
    g_free(r);
}
