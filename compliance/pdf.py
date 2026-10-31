"""Compliance report as PDF (the built-in writer, no dependency)."""
import time

from reporting.pdf import PDF, text_width

COLOURS = {'met': (0.13, 0.55, 0.31), 'partial': (0.85, 0.6, 0.1), 'gap': (0.8, 0.2, 0.2),
           'manual': (0.45, 0.45, 0.5), 'n/a': (0.65, 0.65, 0.68)}


def _wrap(text, size, width):
    words, lines, line = str(text).split(), [], ''
    for w in words:
        cand = f'{line} {w}'.strip()
        if text_width(cand, size) > width and line:
            lines.append(line)
            line = w
        else:
            line = cand
    return lines + ([line] if line else [])


def render(report):
    pdf = PDF()
    y = [0]

    def need(h):
        if y[0] + h > 800:
            pdf.add_page()
            y[0] = 40

    pdf.rect(0, 0, 595, 40, rgb=(0.07, 0.11, 0.2))
    pdf.text(50, 25, 'SentinelEdgeAI', 13, True, 1.0)
    pdf.text(170, 25, f"Compliance evidence: {report['title']}", 10, False, 0.85)
    y[0] = 62
    for line in _wrap(report['disclaimer'], 8, 495):
        pdf.text(50, y[0], line, 8, False, 0.35)
        y[0] += 11
    y[0] += 8
    x = 50
    for status in ('met', 'partial', 'gap', 'manual', 'n/a'):
        pdf.rect(x, y[0], 90, 34, rgb=COLOURS[status])
        pdf.text(x + 8, y[0] + 14, status, 8, False, 1.0)
        pdf.text(x + 8, y[0] + 28, str(report['totals'][status]), 12, True, 1.0)
        x += 99
    y[0] += 50
    for c in report['controls']:
        lines = []
        for e in c['evidence']:
            lines += [(f"[{e['status']}] {part}" if i == 0 else f'      {part}') for i, part in enumerate(_wrap(e['summary'], 8, 400))]
        if not c['evidence']:
            lines = ['Organisational control: evidence comes from outside the appliance.']
        need(16 + 11 * len(lines))
        pdf.rect(50, y[0], 6, 12 + 11 * len(lines), rgb=COLOURS[c['status']])
        pdf.text(62, y[0] + 9, c['id'], 9, True)
        pdf.text(122, y[0] + 9, c['title'][:90], 9, True)
        pdf.text(500, y[0] + 9, c['status'], 8, True, 0.3)
        yy = y[0] + 21
        for line in lines:
            pdf.text(122, yy, line, 8, False, 0.25)
            yy += 11
        y[0] = yy + 6
    pdf.text(50, 825, f"Generated {time.strftime('%Y-%m-%d %H:%M', time.localtime(report['generated']))} by SentinelEdgeAI",
             8, False, 0.5)
    return pdf.output()
