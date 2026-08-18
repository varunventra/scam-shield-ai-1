"""
Forensic PDF Report Generator for the Cyber-Forensic Honeypot.
Generates professional, clean investigation reports.
"""
import os
import random
from datetime import datetime

from fpdf import FPDF

from app.core.logging import logger
from app.models.requests import Message
from app.models.responses import ExtractedIntelligence

# Font paths — absolute so they work regardless of uvicorn launch directory
_FONTS_DIR = os.path.join(os.path.dirname(os.path.dirname(__file__)), "fonts")
_NOTO_REGULAR = os.path.join(_FONTS_DIR, "NotoSans-Regular.ttf")
_NOTO_BOLD    = os.path.join(_FONTS_DIR, "NotoSans-Bold.ttf")
_NOTO_DEVA_REGULAR = os.path.join(_FONTS_DIR, "NotoSansDevanagari-Regular.ttf")
_NOTO_DEVA_BOLD    = os.path.join(_FONTS_DIR, "NotoSansDevanagari-Bold.ttf")


class ForensicPDF(FPDF):
    """Custom PDF class with clean professional styling."""

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.add_font("NotoSans", style="",  fname=_NOTO_REGULAR)
        self.add_font("NotoSans", style="B", fname=_NOTO_BOLD)
        self.add_font("NotoSansDevanagari", style="",  fname=_NOTO_DEVA_REGULAR)
        self.add_font("NotoSansDevanagari", style="B", fname=_NOTO_DEVA_BOLD)
        self.set_fallback_fonts(["NotoSansDevanagari"])

    # ── Clean Professional Palette ──────────────────────────────────────────
    # Backgrounds
    WHITE       = (255, 255, 255)
    OFF_WHITE   = (249, 250, 251)   # #F9FAFB — subtle section backgrounds
    LIGHT_GRAY  = (241, 245, 249)   # #F1F5F9 — table alternates, strips
    BORDER_GRAY = (226, 232, 240)   # #E2E8F0 — all borders / dividers

    # Text
    TEXT_DARK   = (15, 23, 42)      # #0F172A — primary headings
    TEXT_BODY   = (51, 65, 85)      # #334155 — body copy
    TEXT_MUTED  = (100, 116, 139)   # #64748B — labels, meta

    # Brand accent
    ACCENT      = (37, 99, 235)     # #2563EB — accent bars, key values
    ACCENT_LIGHT= (219, 234, 254)   # #DBEAFE — accent tinted backgrounds

    # Status colours (muted, not garish)
    CRIMSON     = (185, 28, 28)     # #B91C1C — SCAM CONFIRMED
    AMBER       = (180, 83, 9)      # #B45309 — HIGH / warning
    GOLD        = (133, 100, 4)     # #856404 — MODERATE
    EMERALD     = (21, 128, 61)     # #15803D — safe / resolved

    # Transcript
    AGENT_BG    = (239, 246, 255)   # #EFF6FF — agent message rows
    SCAMMER_BG  = (254, 242, 242)   # #FEF2F2 — scammer message rows
    AGENT_BORDER= (191, 219, 254)   # #BFDBFE
    SCAMMER_BORDER=(254, 202, 202)  # #FECACA

    def header(self):
        """Override — handled manually."""
        pass

    def footer(self):
        """Minimal page footer."""
        self.set_y(-15)
        self.set_draw_color(*self.BORDER_GRAY)
        self.set_line_width(0.3)
        self.line(15, self.get_y(), 195, self.get_y())
        self.ln(2)
        self.set_font("NotoSans", "", 7)
        self.set_text_color(*self.TEXT_MUTED)
        self.cell(0, 4, f"ScamShield AI  ·  Confidential  ·  Page {self.page_no()}/{{nb}}", align="C")


class ForensicReporter:
    """Generates clean, professional PDF investigation reports."""

    FORENSICS_DIR = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(__file__))), "forensics"
    )

    def __init__(self):
        os.makedirs(self.FORENSICS_DIR, exist_ok=True)

    def _generate_case_id(self, session_id: str) -> str:
        clean_id = session_id.replace("-", "").replace("_", "")[:8].upper()
        if not clean_id:
            clean_id = f"{random.randint(1000, 9999):04d}"  # noqa: S311 — cosmetic case-ID suffix, not a security token
        return f"CFA-{datetime.now().year}-{clean_id}"

    @staticmethod
    def _format_generation_date() -> str:
        """Local server time with an explicit UTC offset, e.g. '30 Jul 2026  10:47 (UTC+05:30)'.

        Message timestamps in the timeline are rendered in local time, so the
        header must be local too — a bare 'UTC' label here previously showed
        local time mislabeled as UTC.
        """
        now = datetime.now().astimezone()
        offset = now.strftime("%z")  # e.g. +0530
        return f"{now:%d %b %Y  %H:%M} (UTC{offset[:3]}:{offset[3:]})"

    def _safe_text(self, text: str) -> str:
        if not text:
            return "N/A"
        replacements = {
            '\u2018': "'", '\u2019': "'",
            '\u201c': '"', '\u201d': '"',
            '\u2013': '-', '\u2014': '--',
            '\u2026': '...',
            '\u00a0': ' ',
            '\u20b9': 'Rs.',
            '\u2022': '*',
            '\u2713': '[Y]',
            '\u2717': '[X]',
        }
        for char, replacement in replacements.items():
            text = text.replace(char, replacement)
        return text

    # ── Public API ─────────────────────────────────────────────────────────

    def generate_forensic_report(
        self,
        session_id: str,
        extracted_intelligence: ExtractedIntelligence,
        conversation_history: list[Message],
        agent_notes: str = "",
        scam_detected: bool = True,
        total_messages: int = 0,
    ) -> str | None:
        """Generate PDF to file. Returns path or None."""
        try:
            case_id = self._generate_case_id(session_id)
            generation_date = self._format_generation_date()
            msg_count = total_messages or len(conversation_history)

            pdf = self._build_pdf(
                case_id, generation_date, msg_count,
                extracted_intelligence, agent_notes, scam_detected,
                conversation_history, duration_seconds=0, repeat_scammer_score=0,
            )
            filename = f"CyberCrime_Report_{case_id}.pdf"
            filepath = os.path.join(self.FORENSICS_DIR, filename)
            pdf.output(filepath)
            logger.info(f"Forensic report generated: {filepath} (Case: {case_id})")
            return filepath
        except Exception as e:
            logger.error(f"Failed to generate forensic report — Session: {session_id}, Error: {e}")
            return None

    def generate_forensic_report_bytes(
        self,
        session_id: str,
        extracted_intelligence: ExtractedIntelligence,
        conversation_history: list[Message],
        agent_notes: str = "",
        scam_detected: bool = True,
        total_messages: int = 0,
        duration_seconds: int = 0,
        repeat_scammer_score: int = 0,
    ) -> bytes | None:
        """Generate PDF and return as bytes for MongoDB storage."""
        try:
            case_id = self._generate_case_id(session_id)
            generation_date = self._format_generation_date()
            msg_count = total_messages or len(conversation_history)

            pdf = self._build_pdf(
                case_id, generation_date, msg_count,
                extracted_intelligence, agent_notes, scam_detected,
                conversation_history, duration_seconds, repeat_scammer_score,
            )
            pdf_bytes = pdf.output()
            logger.info(f"Forensic report bytes generated (Case: {case_id}, {len(pdf_bytes)} bytes)")
            return pdf_bytes
        except Exception as e:
            logger.error(f"Failed to generate forensic report bytes — Session: {session_id}, Error: {e}")
            return None

    # ── Internal builder ───────────────────────────────────────────────────

    def _build_pdf(
        self,
        case_id: str,
        generation_date: str,
        msg_count: int,
        intelligence: ExtractedIntelligence,
        agent_notes: str,
        scam_detected: bool,
        conversation_history: list[Message],
        duration_seconds: int,
        repeat_scammer_score: int,
    ) -> ForensicPDF:
        pdf = ForensicPDF(orientation="P", unit="mm", format="A4")
        pdf.alias_nb_pages()
        pdf.set_auto_page_break(auto=True, margin=22)
        pdf.add_page()

        self._render_header(pdf, case_id, generation_date, scam_detected)
        self._render_intel_summary(pdf, intelligence, duration_seconds, msg_count, repeat_scammer_score)
        self._render_executive_summary(pdf, agent_notes, scam_detected, msg_count, intelligence)
        self._render_suspect_table(pdf, intelligence)
        self._render_behavioral_markers(pdf, intelligence)
        self._render_evidence_log(pdf, conversation_history)
        self._render_forensic_footer(pdf)
        return pdf

    # ── Section renderers ──────────────────────────────────────────────────

    def _render_header(self, pdf: ForensicPDF, case_id: str, generation_date: str, scam_detected: bool):
        """Clean two-tone header: dark top bar + white content area."""
        P = ForensicPDF

        # ── Top bar: solid dark charcoal ─────────────────────────────────
        pdf.set_fill_color(*P.TEXT_DARK)
        pdf.rect(0, 0, 210, 18, "F")

        # Thin accent stripe at very top
        pdf.set_fill_color(*P.ACCENT)
        pdf.rect(0, 0, 210, 1.5, "F")

        # Title in top bar
        pdf.set_y(4)
        pdf.set_font("NotoSans", "B", 10)
        pdf.set_text_color(*P.WHITE)
        pdf.cell(0, 5, "CYBERCRIME FORENSIC INVESTIGATION REPORT", align="C",
                 new_x="LMARGIN", new_y="NEXT")

        pdf.set_font("NotoSans", "", 7)
        pdf.set_text_color(148, 163, 184)   # slate-400
        pdf.cell(0, 4, "ScamShield AI  ·  Autonomous Honeypot Intelligence Division", align="C",
                 new_x="LMARGIN", new_y="NEXT")

        # ── Metadata row below the bar ────────────────────────────────────
        pdf.set_y(22)
        pdf.set_font("NotoSans", "", 8)
        pdf.set_text_color(*P.TEXT_MUTED)

        # Case ID  |  Date  |  Status badge
        meta_items = [
            ("Case ID",    case_id),
            ("Generated",  generation_date),
            ("Investigator", "ScamShield AI (Automated)"),
        ]
        col_w = 63
        for label, value in meta_items:
            pdf.set_font("NotoSans", "B", 7.5)
            pdf.set_text_color(*P.TEXT_MUTED)
            pdf.cell(22, 5, label + ":", new_x="RIGHT")
            pdf.set_font("NotoSans", "", 7.5)
            pdf.set_text_color(*P.TEXT_DARK)
            pdf.cell(col_w - 22, 5, value, new_x="RIGHT")
        pdf.ln(7)

        # Status pill — right-aligned inline with thin border
        pill_w = 40
        pill_x = 210 - 15 - pill_w
        pill_y = 22
        if scam_detected:
            pdf.set_fill_color(254, 242, 242)
            pdf.set_draw_color(*P.CRIMSON)
            pill_text = "SCAM CONFIRMED"
            pill_tc = P.CRIMSON
        else:
            pdf.set_fill_color(240, 253, 244)
            pdf.set_draw_color(*P.EMERALD)
            pill_text = "INCONCLUSIVE"
            pill_tc = P.EMERALD

        pdf.set_line_width(0.4)
        pdf.rect(pill_x, pill_y + 0.5, pill_w, 6, "FD")
        pdf.set_xy(pill_x, pill_y + 0.5)
        pdf.set_font("NotoSans", "B", 7)
        pdf.set_text_color(*pill_tc)
        pdf.cell(pill_w, 6, pill_text, align="C")
        pdf.set_line_width(0.2)

        # Divider
        pdf.set_y(35)
        pdf.set_draw_color(*P.BORDER_GRAY)
        pdf.set_line_width(0.4)
        pdf.line(15, pdf.get_y(), 195, pdf.get_y())
        pdf.set_line_width(0.2)
        pdf.ln(5)

    def _render_section_title(self, pdf: ForensicPDF, number: str, title: str):
        """Render a clean section heading with left accent."""
        P = ForensicPDF
        pdf.ln(2)
        y = pdf.get_y()
        # Thin left accent bar
        pdf.set_fill_color(*P.ACCENT)
        pdf.rect(15, y, 2.5, 7, "F")
        # Section number in accent
        pdf.set_xy(20, y)
        pdf.set_font("NotoSans", "B", 8)
        pdf.set_text_color(*P.ACCENT)
        pdf.cell(8, 7, number, new_x="RIGHT")
        # Title in dark
        pdf.set_font("NotoSans", "B", 10)
        pdf.set_text_color(*P.TEXT_DARK)
        pdf.cell(0, 7, title, new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

    def _render_intel_summary(
        self, pdf: ForensicPDF, intel: ExtractedIntelligence,
        duration_seconds: int, msg_count: int, repeat_scammer_score: int,
    ):
        """Clean stat cards row."""
        P = ForensicPDF

        total_intel = (
            len(intel.phoneNumbers) + len(intel.upiIds) +
            len(intel.bankAccounts) + len(intel.phishingLinks) +
            len(intel.emailAddresses) + len(intel.suspiciousKeywords)
        )

        if duration_seconds >= 60:
            dur_str = f"{duration_seconds // 60}m {duration_seconds % 60}s"
        elif duration_seconds > 0:
            dur_str = f"{duration_seconds}s"
        else:
            dur_str = "—"

        cards = [
            ("Intel Items",     str(total_intel)),
            ("Messages",        str(msg_count)),
            ("Duration",        dur_str),
            ("Phone Numbers",   str(len(intel.phoneNumbers))),
            ("UPI / Payment",   str(len(intel.upiIds))),
            ("Phishing Links",  str(len(intel.phishingLinks))),
        ]
        if repeat_scammer_score > 0:
            cards.append(("Repeat Score", f"{repeat_scammer_score}/100"))

        n = len(cards)
        usable_w = 180   # 15mm margin each side
        card_w = usable_w / n
        card_h = 14
        y = pdf.get_y()

        for i, (label, value) in enumerate(cards):
            x = 15 + i * card_w

            # Card background — alternate subtle tint
            if i % 2 == 0:
                pdf.set_fill_color(*P.OFF_WHITE)
            else:
                pdf.set_fill_color(*P.WHITE)
            pdf.set_draw_color(*P.BORDER_GRAY)
            pdf.rect(x, y, card_w, card_h, "FD")

            # Value (large)
            pdf.set_xy(x, y + 2)
            red_card = (label == "Repeat Score")
            pdf.set_font("NotoSans", "B", 12)
            pdf.set_text_color(*(P.CRIMSON if red_card else P.ACCENT))
            pdf.cell(card_w, 6, value, align="C", new_x="RIGHT")

            # Label (small)
            pdf.set_xy(x, y + 8)
            pdf.set_font("NotoSans", "", 6.5)
            pdf.set_text_color(*P.TEXT_MUTED)
            pdf.cell(card_w, 4, label.upper(), align="C", new_x="RIGHT")

        pdf.set_y(y + card_h + 6)

    def _render_executive_summary(
        self, pdf: ForensicPDF, agent_notes: str, scam_detected: bool,
        msg_count: int, intelligence: ExtractedIntelligence,
    ):
        P = ForensicPDF
        self._render_section_title(pdf, "01", "Incident Analysis")

        # Background box
        y_start = pdf.get_y()
        pdf.set_fill_color(*P.OFF_WHITE)
        pdf.set_draw_color(*P.BORDER_GRAY)
        pdf.rect(15, y_start, 180, 4, "")  # placeholder height, drawn after

        # Two-column meta line
        pdf.set_font("NotoSans", "B", 8.5)
        pdf.set_text_color(*P.TEXT_MUTED)
        pdf.set_x(15)
        pdf.cell(35, 6, "Detection Status:", new_x="RIGHT")
        pdf.set_font("NotoSans", "B", 8.5)
        if scam_detected:
            pdf.set_text_color(*P.CRIMSON)
            pdf.cell(60, 6, "Scam Confirmed", new_x="RIGHT")
        else:
            pdf.set_text_color(*P.EMERALD)
            pdf.cell(60, 6, "Inconclusive", new_x="RIGHT")

        pdf.set_font("NotoSans", "B", 8.5)
        pdf.set_text_color(*P.TEXT_MUTED)
        pdf.cell(30, 6, "Messages:", new_x="RIGHT")
        pdf.set_font("NotoSans", "", 8.5)
        pdf.set_text_color(*P.TEXT_BODY)
        pdf.cell(0, 6, str(msg_count), new_x="LMARGIN", new_y="NEXT")

        # Impersonation targets if present
        targets = getattr(intelligence, 'impersonationTargets', [])
        if targets:
            pdf.set_x(15)
            pdf.set_font("NotoSans", "B", 8.5)
            pdf.set_text_color(*P.TEXT_MUTED)
            pdf.cell(35, 5, "Impersonating:", new_x="RIGHT")
            pdf.set_font("NotoSans", "", 8.5)
            pdf.set_text_color(*P.TEXT_BODY)
            pdf.cell(0, 5, self._safe_text(", ".join(targets)), new_x="LMARGIN", new_y="NEXT")

        # Agent notes
        if agent_notes:
            pdf.ln(2)
            pdf.set_x(15)
            pdf.set_font("NotoSans", "B", 8.5)
            pdf.set_text_color(*P.TEXT_MUTED)
            pdf.cell(35, 5, "Summary:", new_x="LMARGIN", new_y="NEXT")
            pdf.set_x(15)
            pdf.set_font("NotoSans", "", 8.5)
            pdf.set_text_color(*P.TEXT_BODY)
            pdf.multi_cell(180, 5, self._safe_text(agent_notes))

        pdf.ln(5)

    def _render_suspect_table(self, pdf: ForensicPDF, intelligence: ExtractedIntelligence):
        P = ForensicPDF
        self._render_section_title(pdf, "02", "Extracted Intelligence")

        rows = [
            ("Phone Numbers",   ", ".join(intelligence.phoneNumbers)  or "—"),
            ("UPI / Payment IDs", ", ".join(intelligence.upiIds)        or "—"),
            ("Bank Accounts",   ", ".join(intelligence.bankAccounts)   or "—"),
            ("Phishing URLs",   ", ".join(intelligence.phishingLinks)  or "—"),
        ]
        emails = getattr(intelligence, 'emailAddresses', [])
        if emails:
            rows.append(("Email Addresses", ", ".join(emails)))
        amounts = getattr(intelligence, 'amounts', [])
        if amounts:
            rows.append(("Amounts Requested", ", ".join(amounts)))

        label_w = 52
        value_w = 128
        row_h = 9

        # Header row
        pdf.set_fill_color(*P.TEXT_DARK)
        pdf.set_text_color(*P.WHITE)
        pdf.set_font("NotoSans", "B", 8)
        pdf.set_draw_color(*P.TEXT_DARK)
        pdf.set_line_width(0)
        pdf.set_x(15)
        pdf.cell(label_w, row_h, "  Field", border=0, fill=True, new_x="RIGHT")
        pdf.cell(value_w, row_h, "  Extracted Value", border=0, fill=True,
                 new_x="LMARGIN", new_y="NEXT")
        pdf.set_line_width(0.2)

        # Data rows
        for i, (label, value) in enumerate(rows):
            pdf.set_x(15)
            if i % 2 == 0:
                pdf.set_fill_color(*P.LIGHT_GRAY)
            else:
                pdf.set_fill_color(*P.WHITE)

            pdf.set_draw_color(*P.BORDER_GRAY)
            pdf.set_font("NotoSans", "B", 8)
            pdf.set_text_color(*P.TEXT_MUTED)
            pdf.cell(label_w, row_h, f"  {label}", border="LRB", fill=True, new_x="RIGHT")

            # Highlight extracted values in accent if they have data
            if value == "—":
                pdf.set_text_color(*P.TEXT_MUTED)
            else:
                pdf.set_text_color(*P.TEXT_DARK)
            pdf.set_font("NotoSans", "", 8)
            pdf.cell(value_w, row_h, f"  {self._safe_text(value)}", border="LRB",
                     fill=True, new_x="LMARGIN", new_y="NEXT")

        pdf.ln(6)

    def _render_behavioral_markers(self, pdf: ForensicPDF, intelligence: ExtractedIntelligence):
        P = ForensicPDF
        self._render_section_title(pdf, "03", "Behavioral Markers")

        keywords = intelligence.suspiciousKeywords
        if not keywords:
            pdf.set_x(15)
            pdf.set_font("NotoSans", "", 8.5)
            pdf.set_text_color(*P.TEXT_MUTED)
            pdf.cell(0, 6, "No high-risk keywords identified.", new_x="LMARGIN", new_y="NEXT")
            pdf.ln(3)
            return

        count = len(keywords)
        if count >= 8:
            level, tc, bg, bc = "CRITICAL", P.CRIMSON, (254, 242, 242), P.CRIMSON
        elif count >= 4:
            level, tc, bg, bc = "HIGH", P.AMBER,  (255, 247, 237), P.AMBER
        else:
            level, tc, bg, bc = "MODERATE", P.GOLD, (254, 252, 232), P.GOLD

        # Threat level row
        pdf.set_x(15)
        pdf.set_fill_color(*bg)
        pdf.set_draw_color(*bc)
        pdf.set_line_width(0.3)
        pill_w = 35
        pdf.rect(15, pdf.get_y(), pill_w, 7, "FD")
        pdf.set_xy(15, pdf.get_y())
        pdf.set_font("NotoSans", "B", 8)
        pdf.set_text_color(*tc)
        pdf.cell(pill_w, 7, level, align="C", new_x="RIGHT")

        pdf.set_font("NotoSans", "", 8.5)
        pdf.set_text_color(*P.TEXT_BODY)
        pdf.cell(0, 7, f"   {count} suspicious keyword(s) flagged", new_x="LMARGIN", new_y="NEXT")
        pdf.set_line_width(0.2)
        pdf.ln(3)

        # Keyword chips
        pdf.set_font("NotoSans", "", 7.5)
        x_start = 17
        x = x_start
        max_x = 193
        current_y = pdf.get_y()

        for kw in sorted(keywords):
            kw_safe = self._safe_text(kw)
            w = pdf.get_string_width(kw_safe) + 10
            if x + w > max_x:
                current_y += 8
                x = x_start
            if current_y > 260:
                pdf.add_page()
                current_y = pdf.get_y()
                x = x_start

            pdf.set_xy(x, current_y)
            pdf.set_fill_color(*P.ACCENT_LIGHT)
            pdf.set_draw_color(191, 219, 254)   # blue-200
            pdf.set_text_color(*P.ACCENT)
            pdf.cell(w, 6, f" {kw_safe} ", border=1, fill=True, new_x="RIGHT")
            x += w + 3

        pdf.set_y(current_y + 10)

    def _render_evidence_log(self, pdf: ForensicPDF, conversation_history: list[Message]):
        P = ForensicPDF
        pdf.add_page()
        self._render_section_title(pdf, "04", "Evidence Log  —  Full Transcript")

        if not conversation_history:
            pdf.set_x(15)
            pdf.set_font("NotoSans", "", 8.5)
            pdf.set_text_color(*P.TEXT_MUTED)
            pdf.cell(0, 6, "No conversation data available.", new_x="LMARGIN", new_y="NEXT")
            return

        # Entry count
        pdf.set_x(15)
        pdf.set_font("NotoSans", "", 8)
        pdf.set_text_color(*P.TEXT_MUTED)
        pdf.cell(0, 5, f"{len(conversation_history)} message(s) on record",
                 new_x="LMARGIN", new_y="NEXT")
        pdf.ln(3)

        for idx, msg in enumerate(conversation_history):
            is_agent = msg.sender in ("user", "agent", "honeypot")
            sender_label = "ScamShield Agent" if is_agent else "Suspect (Scammer)"

            if pdf.get_y() > 258:
                pdf.add_page()

            # Row background and border
            if is_agent:
                header_bg  = P.AGENT_BG
                header_tc  = (30, 64, 175)    # blue-800
                body_bg    = P.WHITE
                left_bar   = P.ACCENT
            else:
                header_bg  = P.SCAMMER_BG
                header_tc  = (153, 27, 27)    # red-800
                body_bg    = P.WHITE
                left_bar   = P.CRIMSON

            # Left accent bar
            y_start = pdf.get_y()
            pdf.set_fill_color(*left_bar)
            pdf.rect(15, y_start, 1.5, 6, "F")

            # Header row
            pdf.set_fill_color(*header_bg)
            pdf.set_draw_color(*P.BORDER_GRAY)
            pdf.rect(16.5, y_start, 178.5, 6, "FD")

            pdf.set_xy(18, y_start)
            pdf.set_font("NotoSans", "B", 7.5)
            pdf.set_text_color(*header_tc)

            ts = ""
            if hasattr(msg, 'timestamp') and msg.timestamp:
                try:
                    ts_dt = datetime.fromtimestamp(msg.timestamp / 1000)
                    ts = f"  ·  {ts_dt.strftime('%H:%M:%S')}"
                except (ValueError, OSError):
                    pass

            pdf.cell(0, 6, f"[{idx + 1:02d}]  {sender_label}{ts}", new_x="LMARGIN", new_y="NEXT")

            # Body
            body_y = pdf.get_y()
            pdf.set_fill_color(*left_bar)
            body_text = self._safe_text(msg.text)
            # Estimate body height first pass: ~4.5mm per line, ~80 chars per line at 8pt
            est_lines = max(1, len(body_text) // 80 + 1)
            est_h = est_lines * 4.5 + 5
            pdf.rect(15, body_y, 1.5, est_h, "F")

            pdf.set_fill_color(*body_bg)
            pdf.set_draw_color(*P.BORDER_GRAY)
            pdf.rect(16.5, body_y, 178.5, est_h, "FD")

            pdf.set_xy(19, body_y + 2)
            pdf.set_font("NotoSans", "", 8)
            pdf.set_text_color(*P.TEXT_BODY)
            pdf.multi_cell(174, 4.5, body_text)

            # Push cursor past the box
            pdf.set_y(max(pdf.get_y(), body_y + est_h) + 2)

    def _render_forensic_footer(self, pdf: ForensicPDF):
        P = ForensicPDF
        if pdf.get_y() > 248:
            pdf.add_page()

        pdf.ln(8)

        # Thin rule
        pdf.set_draw_color(*P.BORDER_GRAY)
        pdf.set_line_width(0.3)
        pdf.line(15, pdf.get_y(), 195, pdf.get_y())
        pdf.ln(5)

        # Integrity notice box
        y = pdf.get_y()
        pdf.set_fill_color(*P.OFF_WHITE)
        pdf.set_draw_color(*P.BORDER_GRAY)
        pdf.rect(15, y, 180, 18, "FD")

        # Left accent bar on box
        pdf.set_fill_color(*P.ACCENT)
        pdf.rect(15, y, 2, 18, "F")

        pdf.set_xy(20, y + 3)
        pdf.set_font("NotoSans", "B", 7.5)
        pdf.set_text_color(*P.TEXT_DARK)
        pdf.cell(0, 4, "Forensic Integrity Notice", new_x="LMARGIN", new_y="NEXT")

        pdf.set_x(20)
        pdf.set_font("NotoSans", "", 7)
        pdf.set_text_color(*P.TEXT_MUTED)
        notice = (
            "This document contains autonomously extracted digital evidence collected via a passive AI honeypot. "
            "Data integrity has been preserved for law enforcement review. "
            "No personally identifiable information of legitimate users was compromised during this engagement."
        )
        pdf.multi_cell(173, 3.8, notice)
