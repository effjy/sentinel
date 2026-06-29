#include "scan.hpp"
#include <string.h>
#include <stdio.h>
#include <stdlib.h>

/* ------------------------------------------------------------------ */
/* Plain-text rendering                                                */
/* ------------------------------------------------------------------ */

char *report_to_text(const ScanReport *r) {
    GString *s = g_string_new(NULL);
    g_string_append(s, "ENVISION SECURITY POSTURE REPORT\n");
    g_string_append(s, "================================\n\n");
    g_string_append_printf(s, "Host     : %s\n", r->hostname);
    g_string_append_printf(s, "OS       : %s\n", r->os_pretty);
    g_string_append_printf(s, "Kernel   : %s\n", r->kernel);
    g_string_append_printf(s, "Scanned  : %s\n\n", r->scanned_at);

    g_string_append(s, "Summary: ");
    for (int sev = SEV_CRITICAL; sev >= SEV_OK; sev--)
        g_string_append_printf(s, "%s=%d  ",
                               severity_name((Severity)sev), r->counts[sev]);
    g_string_append(s, "\n\n");

    /* Sort: most severe first. */
    for (int sev = SEV_CRITICAL; sev >= SEV_OK; sev--) {
        for (guint i = 0; i < r->items->len; i++) {
            Finding *f = static_cast<Finding *>(g_ptr_array_index(r->items, i));
            if (f->severity != (Severity)sev) continue;
            g_string_append_printf(s, "[%s] (%s) %s\n",
                                   severity_name(f->severity),
                                   f->category, f->title);
            if (f->detail && *f->detail)
                g_string_append_printf(s, "    Observed: %s\n", f->detail);
            if (f->suggestion && *f->suggestion)
                g_string_append_printf(s, "    Advice  : %s\n", f->suggestion);
            if (f->fix_command)
                g_string_append_printf(s, "    Fix     : %s\n", f->fix_command);
            g_string_append(s, "\n");
        }
    }
    return g_string_free(s, FALSE);
}

/* ------------------------------------------------------------------ */
/* LaTeX rendering                                                     */
/* ------------------------------------------------------------------ */

/* Escape a string for LaTeX. Caller frees. */
static char *tex_escape(const char *in) {
    if (!in) return g_strdup("");
    GString *o = g_string_new(NULL);
    for (const char *p = in; *p; p++) {
        switch (*p) {
            case '\\': g_string_append(o, "\\textbackslash{}"); break;
            case '&': case '%': case '$': case '#': case '_':
            case '{': case '}':
                g_string_append_c(o, '\\'); g_string_append_c(o, *p); break;
            case '~': g_string_append(o, "\\textasciitilde{}"); break;
            case '^': g_string_append(o, "\\textasciicircum{}"); break;
            case '\n': g_string_append(o, "\\newline "); break;
            default:
                /* Drop non-ASCII bytes: stock pdflatex has no glyph set up for
                 * arbitrary Unicode (e.g. the ● systemd bullet) and would abort. */
                if ((unsigned char)*p >= 0x80 || (unsigned char)*p < 0x20)
                    break;
                g_string_append_c(o, *p);
        }
    }
    return g_string_free(o, FALSE);
}

/* Monospace-escape (for verbatim-ish detail/fix). Keep newlines as breaks. */
static char *tex_escape_mono(const char *in) {
    return tex_escape(in);
}

char *report_to_latex(const ScanReport *r) {
    GString *s = g_string_new(NULL);
    char *host = tex_escape(r->hostname);
    char *os   = tex_escape(r->os_pretty);
    char *kern = tex_escape(r->kernel);
    char *when = tex_escape(r->scanned_at);

    g_string_append(s,
        "\\documentclass[11pt]{article}\n"
        "\\usepackage[margin=2cm]{geometry}\n"
        "\\usepackage[table]{xcolor}\n"
        "\\usepackage{longtable}\n"
        "\\usepackage{enumitem}\n"
        "\\usepackage{parskip}\n"
        "\\usepackage{tcolorbox}\n"
        "\\usepackage{hyperref}\n"
        "\\hypersetup{colorlinks=true,linkcolor=blue}\n"
        "\\definecolor{sevok}{HTML}{2E7D32}\n"
        "\\definecolor{sevlow}{HTML}{0277BD}\n"
        "\\definecolor{sevmed}{HTML}{F9A825}\n"
        "\\definecolor{sevhigh}{HTML}{E65100}\n"
        "\\definecolor{sevcrit}{HTML}{C62828}\n"
        "\\setlength{\\parindent}{0pt}\n"
        "\\begin{document}\n");

    g_string_append(s,
        "\\begin{center}\n"
        "{\\Huge\\bfseries Envision Security Report}\\\\[4pt]\n"
        "{\\large System hardening assessment}\n"
        "\\end{center}\n\\vspace{6pt}\n");

    g_string_append_printf(s,
        "\\begin{tabular}{ll}\n"
        "\\textbf{Host} & %s\\\\\n"
        "\\textbf{Operating system} & %s\\\\\n"
        "\\textbf{Kernel} & %s\\\\\n"
        "\\textbf{Scanned at} & %s\\\\\n"
        "\\end{tabular}\n\\vspace{8pt}\n\n",
        host, os, kern, when);

    /* Summary box. */
    g_string_append(s, "\\begin{tcolorbox}[colback=black!5,colframe=black!40,"
                       "title=Summary]\n");
    const char *cols[] = {"sevok","sevlow","sevmed","sevhigh","sevcrit"};
    for (int sev = SEV_CRITICAL; sev >= SEV_OK; sev--)
        g_string_append_printf(s, "\\textcolor{%s}{\\textbf{%s: %d}}\\quad ",
                               cols[sev], severity_name((Severity)sev), r->counts[sev]);
    g_string_append(s, "\n\\end{tcolorbox}\n\n");

    for (int sev = SEV_CRITICAL; sev >= SEV_OK; sev--) {
        for (guint i = 0; i < r->items->len; i++) {
            Finding *f = static_cast<Finding *>(g_ptr_array_index(r->items, i));
            if (f->severity != (Severity)sev) continue;
            char *title = tex_escape(f->title);
            char *cat   = tex_escape(f->category);
            char *det   = tex_escape_mono(f->detail);
            char *sug   = tex_escape(f->suggestion);
            g_string_append_printf(s,
                "\\begin{tcolorbox}[colback=white,colframe=%s,"
                "title={\\textbf{[%s]} %s \\hfill\\small %s}]\n",
                cols[sev], severity_name((Severity)sev), title, cat);
            if (f->detail && *f->detail)
                g_string_append_printf(s, "\\textbf{Observed:} %s\\par\\smallskip\n", det);
            if (f->suggestion && *f->suggestion)
                g_string_append_printf(s, "\\textbf{Advice:} %s\\par\\smallskip\n", sug);
            if (f->fix_command) {
                char *fix = tex_escape_mono(f->fix_command);
                g_string_append_printf(s,
                    "\\textbf{Fix:}\\\\\n{\\ttfamily\\small %s}\n", fix);
                g_free(fix);
            }
            g_string_append(s, "\\end{tcolorbox}\n\\vspace{4pt}\n\n");
            g_free(title); g_free(cat); g_free(det); g_free(sug);
        }
    }

    g_string_append(s,
        "\\vfill\\begin{center}\\small\n"
        "Generated by \\textbf{Envision} --- "
        "by Jean-Francois Lachance-Caumartin.\\\\\n"
        "This report reflects the system state at scan time; re-scan after "
        "applying fixes.\n"
        "\\end{center}\n"
        "\\end{document}\n");

    g_free(host); g_free(os); g_free(kern); g_free(when);
    return g_string_free(s, FALSE);
}

/* ------------------------------------------------------------------ */
/* PDF generation via pdflatex                                         */
/* ------------------------------------------------------------------ */

gboolean report_write_pdf(const char *latex_src, const char *out_path,
                          char **err_out) {
    if (err_out) *err_out = NULL;
    char *tmpl = g_strdup("/tmp/envision-XXXXXX");
    char *dir  = g_mkdtemp(tmpl);
    if (!dir) {
        if (err_out) *err_out = g_strdup("Could not create temp directory.");
        g_free(tmpl);
        return FALSE;
    }
    char *texpath = g_build_filename(dir, "report.tex", NULL);
    GError *werr = NULL;
    if (!g_file_set_contents(texpath, latex_src, -1, &werr)) {
        if (err_out) *err_out = g_strdup(werr ? werr->message : "write failed");
        if (werr) g_error_free(werr);
        g_free(texpath); g_free(dir);
        return FALSE;
    }

    /* Run pdflatex twice for references/longtable; nonstop mode. */
    char *cmd = g_strdup_printf(
        "cd '%s' && pdflatex -interaction=nonstopmode -halt-on-error report.tex "
        ">/dev/null 2>&1 && pdflatex -interaction=nonstopmode -halt-on-error "
        "report.tex >/dev/null 2>&1", dir);
    int rc = system(cmd);
    g_free(cmd);

    char *pdfpath = g_build_filename(dir, "report.pdf", NULL);
    gboolean ok = FALSE;
    if (g_file_test(pdfpath, G_FILE_TEST_EXISTS)) {
        char *data = NULL; gsize len = 0;
        if (g_file_get_contents(pdfpath, &data, &len, &werr)) {
            if (g_file_set_contents(out_path, data, len, &werr))
                ok = TRUE;
            g_free(data);
        }
        if (!ok && err_out && werr)
            *err_out = g_strdup(werr->message);
        if (werr) g_error_free(werr);
    } else if (err_out) {
        *err_out = g_strdup_printf("pdflatex did not produce a PDF (exit %d). "
                                   "Is texlive installed?", rc);
    }

    /* Best-effort cleanup. */
    char *rm = g_strdup_printf("rm -rf '%s'", dir);
    if (system(rm) != 0) { /* ignore */ }
    g_free(rm);
    g_free(pdfpath); g_free(texpath); g_free(dir);
    return ok;
}
