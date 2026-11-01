#!/usr/bin/env python3
"""Assemble the GitHub Pages documentation site from the repository's own Markdown.

    python scripts/build_docs_site.py _site_src      # then Jekyll builds it (.github/workflows/pages.yml)

Pages keep their repository paths (README.md becomes index.md), get Just the Docs front matter for the
navigation, and are wrapped in {% raw %} so code samples containing {{ }} are not treated as Liquid.
Links to published pages stay relative (jekyll-relative-links turns .md into .html); links to anything else
(code, configuration, unpublished notes) become links to the file on GitHub, so nothing on the site is broken.
"""
import os
import re
import sys

ROOT = os.path.abspath(os.path.join(os.path.dirname(__file__), '..'))
REPO = 'https://github.com/vishwa-10147/SentinelEdgeAI'
BRANCH = 'main'

# (source path, title, parent or None, nav order)
PAGES = [
    ('README.md', 'Home', None, 1),
    ('EXPLAIN.md', 'How it works', None, 2),
    ('docs/ADMIN_GUIDE.md', 'Admin guide', 'Operate', 1),
    ('docs/RUNBOOKS.md', 'Runbooks', 'Operate', 2),
    ('docs/TROUBLESHOOTING.md', 'Troubleshooting', 'Operate', 3),
    ('deploy/README.md', 'Deployment', 'Deploy', 1),
    ('deploy/pi/README.md', 'Raspberry Pi', 'Deploy', 2),
    ('deploy/pi/README_ENFORCEMENT.md', 'Turning on enforcement', 'Deploy', 3),
    ('deploy/jetson/README.md', 'Jetson brain', 'Deploy', 4),
    ('deploy/fleet-hosted/README.md', 'Hosted fleet console', 'Deploy', 5),
    ('deploy/monitoring/README.md', 'Monitoring', 'Deploy', 6),
    ('hardware/sentineledge-duo/BUILD_GUIDE.md', 'Hardware (SentinelEdge Duo)', 'Deploy', 7),
    ('docs/API.md', 'API reference', 'Integrate', 1),
    ('docs/EXTENSIONS.md', 'Extensions', 'Integrate', 2),
    ('examples/extensions/README.md', 'Example extensions', 'Integrate', 3),
    ('frontend/README.md', 'Web console', 'Integrate', 4),
    ('docs/EVALUATION.md', 'Detection evaluation', 'Evidence', 1),
    ('docs/PERFORMANCE.md', 'Performance', 'Evidence', 2),
    ('tests/live/README.md', 'Live integration tests', 'Evidence', 3),
    ('docs/PENTEST_SCOPE.md', 'Penetration-test scope', 'Evidence', 4),
    ('docs/BETA_PROGRAM.md', 'Beta programme', 'Evidence', 5),
    ('SECURITY.md', 'Security', None, 7),
    ('PLAN.md', 'Roadmap', None, 8),
    ('CHANGELOG.md', 'Changelog', None, 9),
]
PARENTS = {'Operate': 3, 'Deploy': 4, 'Integrate': 5, 'Evidence': 6}
LINK = re.compile(r'(?<!!)\[([^\]]*)\]\(([^)\s]+)\)')

CONFIG = """title: SentinelEdgeAI
description: Offline network detection and response with an adaptive firewall, for networks that have no security team.
remote_theme: just-the-docs/just-the-docs@v0.10.1
plugins: [jekyll-remote-theme, jekyll-relative-links, jekyll-seo-tag]
relative_links: {enabled: true, collections: false}
url: https://vishwa-10147.github.io
baseurl: /SentinelEdgeAI
color_scheme: light
search_enabled: true
heading_anchors: true
aux_links:
  GitHub: [https://github.com/vishwa-10147/SentinelEdgeAI]
  Releases: [https://github.com/vishwa-10147/SentinelEdgeAI/releases]
footer_content: "Apache-2.0 · <a href=\\"https://github.com/vishwa-10147/SentinelEdgeAI\\">SentinelEdgeAI on GitHub</a>"
gh_edit_link: true
gh_edit_link_text: Edit this page on GitHub
gh_edit_repository: https://github.com/vishwa-10147/SentinelEdgeAI
gh_edit_branch: main
gh_edit_view_mode: tree
exclude: [Gemfile, Gemfile.lock]
"""


def published():
    return {src for src, *_ in PAGES}


def rewrite(text, src):
    base = os.path.dirname(src)
    pages = published()

    def fix(m):
        label, target = m.group(1), m.group(2)
        if re.match(r'^[a-z]+:', target) or target.startswith('#') or target.startswith('/'):
            return m.group(0)
        path, _, anchor = target.partition('#')
        resolved = os.path.normpath(os.path.join(base, path)).replace(os.sep, '/')
        frag = f'#{anchor}' if anchor else ''
        if resolved in pages:
            if resolved == 'README.md':                     # the home page
                rel = os.path.relpath('index.md', base or '.').replace(os.sep, '/')
                return f'[{label}]({rel}{frag})'
            return m.group(0)
        if resolved.startswith('..'):
            return m.group(0)
        kind = 'tree' if os.path.isdir(os.path.join(ROOT, resolved)) else 'blob'
        return f'[{label}]({REPO}/{kind}/{BRANCH}/{resolved}{frag})'

    return LINK.sub(fix, text)


def build(out):
    os.makedirs(out, exist_ok=True)
    with open(os.path.join(out, '_config.yml'), 'w', encoding='utf-8') as f:
        f.write(CONFIG)
    for parent, order in PARENTS.items():
        slug = parent.lower()
        with open(os.path.join(out, f'{slug}.md'), 'w', encoding='utf-8') as f:
            f.write(f'---\ntitle: {parent}\nnav_order: {order}\nhas_children: true\npermalink: /{slug}/\n---\n\n'
                    f'# {parent}\n')
    for src, title, parent, order in PAGES:
        with open(os.path.join(ROOT, src), encoding='utf-8') as f:
            text = f.read()
        text = rewrite(text, src)
        if src == 'README.md':
            text = text.replace('<div align="center">', '<div align="center" markdown="1">', 1)
        dest = 'index.md' if src == 'README.md' else src
        front = [f'title: "{title}"', f'nav_order: {order}']
        if parent:
            front.append(f'parent: {parent}')
        if src == 'README.md':
            front += ['permalink: /', 'nav_exclude: false']
        os.makedirs(os.path.dirname(os.path.join(out, dest)) or out, exist_ok=True)
        with open(os.path.join(out, dest), 'w', encoding='utf-8') as f:
            f.write('---\n' + '\n'.join(front) + '\n---\n\n{% raw %}\n' + text.replace('{% endraw %}', '')
                    + '\n{% endraw %}\n')
    return len(PAGES)


if __name__ == '__main__':
    out = sys.argv[1] if len(sys.argv) > 1 else '_site_src'
    print(f'{build(out)} pages -> {out}')
