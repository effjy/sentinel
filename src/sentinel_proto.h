// sentinel_proto.h — shared contract between sentinel-daemon (root) and the
// sentinel GUI (your user). One Unix-domain socket carries two streams:
//
//   * the per-process outbound FIREWALL (ported from Warden), and
//   * continuous security-POSTURE scanning (ported from Envision), which the
//     daemon re-runs on an interval and diffs so the GUI can show what changed.
//
// The wire format is the same tiny newline-delimited, tab-separated text Warden
// used — trivial to parse on both sides and easy to eyeball with socat/nc. The
// only twist is that posture findings carry multi-line prose, so those fields are
// base64-encoded (see b64_encode/b64_decode below) to stay tab/newline-safe.
//
//   daemon -> gui   HELLO\t<version>
//                   -- firewall --
//                   ASK\t<id>\t<proto>\t<pid>\t<comm>\t<exe>\t<dst_ip>\t<dst_port>
//                   EVENT\t<verdict>\t<exe>\t<dst_ip>\t<dst_port>\t<reason>
//                   -- posture (a full snapshot is framed PBEGIN .. PEND) --
//                   PBEGIN\t<scanned_at_b64>\t<c0>\t<c1>\t<c2>\t<c3>\t<c4>
//                   PFINDING\t<sev>\t<cat_b64>\t<title_b64>\t<detail_b64>\t<sugg_b64>\t<fix_b64>
//                   PEND
//                   PALERT\t<sev>\t<cat_b64>\t<title_b64>      (a NEW/worsened finding)
//
//   gui    -> daemon VERDICT\t<id>\t<allow|deny>\t<once|forever>
//                   RULE\t<allow|deny>\t<exe>          (add/replace a stored rule)
//                   DELRULE\t<exe>                      (forget a stored rule)
//                   SCANNOW                             (request an immediate scan)
//
// Author: Jean-Francois Lachance-Caumartin
#pragma once

#include <string>

#define SENTINEL_VERSION   "1.0.0"
#define SENTINEL_SOCK      "/run/sentinel.sock"   // created by the root daemon
#define SENTINEL_RULES     "/etc/sentinel/rules.conf"
#define SENTINEL_QUEUE_NUM 0                       // nfnetlink queue number
#define SENTINEL_NFT_TABLE "sentinel"              // nftables table name

// Verdict requested when a new connection has no stored rule and no GUI is
// connected to decide. Fail-open keeps a headless box from losing all egress;
// the nftables rule is also installed with `bypass` for the same reason.
#define SENTINEL_DEFAULT_NO_UI_ACCEPT 1

// How long the daemon waits for the user to answer a firewall prompt before
// falling back to SENTINEL_DEFAULT_NO_UI_ACCEPT (milliseconds).
#define SENTINEL_PROMPT_TIMEOUT_MS 20000

// How often the daemon re-runs the posture scan, in seconds. Overridable at
// runtime with $SENTINEL_SCAN_INTERVAL. The scan runs on a worker thread so it
// never stalls firewall decisions.
#define SENTINEL_SCAN_INTERVAL_S 60

// ---------------------------------------------------------------------------
// Minimal base64 (RFC 4648) — header-only so both binaries share one copy.
// Used only for the posture prose fields, which can contain tabs/newlines.
// ---------------------------------------------------------------------------
namespace sentinel_b64 {

inline std::string encode(const std::string &in) {
    static const char *T =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((in.size() + 2) / 3) * 4);
    size_t i = 0;
    while (i + 3 <= in.size()) {
        unsigned n = (unsigned char)in[i] << 16 | (unsigned char)in[i + 1] << 8 |
                     (unsigned char)in[i + 2];
        out += T[(n >> 18) & 63]; out += T[(n >> 12) & 63];
        out += T[(n >> 6) & 63];  out += T[n & 63];
        i += 3;
    }
    if (i + 1 == in.size()) {
        unsigned n = (unsigned char)in[i] << 16;
        out += T[(n >> 18) & 63]; out += T[(n >> 12) & 63]; out += "==";
    } else if (i + 2 == in.size()) {
        unsigned n = (unsigned char)in[i] << 16 | (unsigned char)in[i + 1] << 8;
        out += T[(n >> 18) & 63]; out += T[(n >> 12) & 63];
        out += T[(n >> 6) & 63];  out += '=';
    }
    return out;
}

inline int val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

inline std::string decode(const std::string &in) {
    std::string out;
    int buf = 0, bits = 0;
    for (char c : in) {
        if (c == '=' || c == '\n' || c == '\r') continue;
        int v = val(c);
        if (v < 0) continue;
        buf = (buf << 6) | v; bits += 6;
        if (bits >= 8) { bits -= 8; out += (char)((buf >> bits) & 0xFF); }
    }
    return out;
}

} // namespace sentinel_b64
