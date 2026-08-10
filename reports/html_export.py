"""Export an audit report HTML file (Phase 18)."""

from pathlib import Path

from utils import logger
from utils.formatting import render_html_report

log = logger.get_logger("reports.html")


def export_html(records, path, summary=None, title="Feluda Audit Report", browser_url_rows=None):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    html = render_html_report(records, summary=summary, title=title, browser_url_rows=browser_url_rows)
    try:
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(html)
        log.info("HTML audit report written to %s", path)
    except OSError as exc:
        log.error("HTML export failed: %s", exc)
        raise
    return path

