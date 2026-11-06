# zen/html_report.py
from pathlib import Path
from jinja2 import Template
from datetime import datetime

HTML_TEMPLATE = """
<!DOCTYPE html>
<html lang="de">
<head>
    <meta charset="UTF-8">
    <title>ZenPCanalys — Sicherheitsbericht</title>
    <style>
        body { font-family: 'Segoe UI', Arial, sans-serif; background: #0d1117; color: #e6edf3; margin: 0; padding: 40px; }
        h1 { color: #58a6ff; margin-bottom: 5px; }
        .meta { color: #8b949e; font-size: 14px; margin-bottom: 30px; }
        .summary { display: flex; gap: 20px; margin-bottom: 30px; }
        .card { background: #161b22; border: 1px solid #30363d; border-radius: 12px; padding: 20px; flex: 1; text-align: center; }
        .card .value { font-size: 32px; font-weight: bold; }
        .card .label { color: #8b949e; font-size: 12px; margin-top: 4px; text-transform: uppercase; letter-spacing: 1px; }
        table { width: 100%; border-collapse: collapse; background: #161b22; border-radius: 12px; overflow: hidden; border: 1px solid #30363d; }
        th { background: #21262d; color: #8b949e; padding: 12px; text-align: left; font-size: 12px; font-weight: 600; text-transform: uppercase; }
        td { padding: 10px 12px; border-bottom: 1px solid #30363d; font-size: 13px; color: #c9d1d9; }
        tr:last-child td { border-bottom: none; }
        tr:hover td { background: #1c2128; }
        .critical { color: #f85149; font-weight: bold; }
        .high { color: #f0883e; font-weight: bold; }
        .medium { color: #d29922; font-weight: bold; }
        .low { color: #58a6ff; font-weight: bold; }
        .informational { color: #8b949e; }
        .footer { margin-top: 40px; color: #8b949e; font-size: 11px; text-align: center; }
    </style>
</head>
<body>
    <h1>🐈 ZenPCanalys — Sicherheitsbericht</h1>
    <div class="meta">
        <strong>Datum:</strong> {{ scan_time }}<br>
        <strong>Quelle:</strong> {{ file }}
    </div>

    <div class="summary">
        <div class="card"><div class="value" style="color: #58a6ff;">{{ total_events }}</div><div class="label">Ereignisse</div></div>
        <div class="card"><div class="value" style="color: #f85149;">{{ total_matches }}</div><div class="label">Treffer</div></div>
        <div class="card"><div class="value" style="color: #d29922;">{{ rules_count }}</div><div class="label">Regeln getroffen</div></div>
    </div>

    <table>
        <thead>
            <tr>
                <th>Regel</th>
                <th>Schwere</th>
                <th>Ereignis #</th>
                <th>Zeit</th>
                <th>Details</th>
            </tr>
        </thead>
        <tbody>
        {% for m in matches %}
            <tr>
                <td style="font-weight: 500;">{{ m.rule_title }}</td>
                <td class="{{ m.level }}">{{ m.level.upper() }}</td>
                <td>{{ m.event_index }}</td>
                <td>{{ m.event.get('TimeCreated', '-') }}</td>
                <td style="font-family: monospace; font-size: 11px; color: #8b949e;">{{ m.event | string | truncate(80) }}</td>
            </tr>
        {% endfor %}
        </tbody>
    </table>

    <div class="footer">
        Generiert von ZenPCanalys v0.3.0 — Mao Mao Edition<br>
        <em>„Scharfe Krallen für scharfe Logs“</em>
    </div>
</body>
</html>
"""

def generate_html_report(report: dict, output_path: Path):
    template = Template(HTML_TEMPLATE)
    html = template.render(
        scan_time=report.get("scan_time", datetime.now().isoformat()),
        file=report.get("file", "Unbekannt"),
        total_events=report.get("total_events", 0),
        total_matches=report.get("total_matches", 0),
        rules_count=len(report.get("rules_with_matches", [])),
        matches=report.get("matches", []),
    )
    output_path.write_text(html, encoding="utf-8")
    return output_path