#ifndef ENVISION_SCAN_HPP
#define ENVISION_SCAN_HPP

#include <glib.h>

/* Severity levels for a finding. Ordered by increasing seriousness so the
 * report can be sorted and colour-coded consistently. */
enum Severity {
    SEV_OK = 0,      /* informational: this check passed                    */
    SEV_LOW,         /* minor hardening opportunity                         */
    SEV_MEDIUM,      /* should be addressed                                 */
    SEV_HIGH,        /* serious exposure                                    */
    SEV_CRITICAL     /* fix immediately                                     */
};

/* A single result produced by a check. All strings are owned by the struct
 * and freed by finding_free(). */
struct Finding {
    char    *category;     /* grouping, e.g. "Network", "SSH", "Accounts"   */
    char    *title;        /* short human title of the finding              */
    Severity severity;     /* how bad it is                                 */
    char    *detail;       /* what was observed on this system              */
    char    *suggestion;   /* prose advice on what to do                    */
    char    *fix_command;  /* copy/paste shell command (may be NULL)        */
};

/* List of findings plus summary counters. */
struct ScanReport {
    GPtrArray *items;          /* of Finding*                               */
    int        counts[5];      /* indexed by Severity                       */
    char      *hostname;
    char      *os_pretty;
    char      *kernel;
    char      *scanned_at;     /* ISO-ish timestamp string                  */
    gboolean   firewall_active;/* set by the firewall check, read by others */
    gboolean   is_root;        /* whether the scan ran with full privilege  */
};

/* Callback invoked once per completed check so the UI can show progress. */
typedef void (*ScanProgressFn)(const char *category, double fraction,
                               gpointer user_data);

const char *severity_name(Severity s);
const char *severity_color(Severity s);   /* "#rrggbb" for the UI           */

/* Run the full scan synchronously. Safe to call from a worker thread. */
ScanReport *scan_run(ScanProgressFn progress, gpointer user_data);
void        scan_report_free(ScanReport *r);

/* Render the report to LaTeX source. Caller owns the returned string. */
char *report_to_latex(const ScanReport *r);

/* Render a plain-text version (for on-screen / .txt export). */
char *report_to_text(const ScanReport *r);

/* Compile LaTeX source to a PDF at out_path using pdflatex.
 * Returns TRUE on success; on failure sets *err_out (caller frees). */
gboolean report_write_pdf(const char *latex_src, const char *out_path,
                          char **err_out);

#endif /* ENVISION_SCAN_HPP */
