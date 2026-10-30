"""A minimal PDF 1.4 writer: pages, Helvetica text, filled rectangles and lines.

Enough for tabular security reports without a third-party dependency. Text
is encoded as WinAnsi (Latin-1); other characters are replaced with '?'.
"""
import zlib

A4 = (595, 842)


def _esc(text):
    data = str(text).encode('latin-1', 'replace').decode('latin-1')
    return data.replace('\\', '\\\\').replace('(', '\\(').replace(')', '\\)')


# average Helvetica glyph widths (1/1000 em), good enough for layout and truncation
def text_width(text, size, bold=False):
    return len(str(text)) * size * (0.56 if bold else 0.52)


class PDF:
    def __init__(self, size=A4):
        self.w, self.h = size
        self.pages = []
        self.add_page()

    def add_page(self):
        self.pages.append([])
        return self

    def _op(self, s):
        self.pages[-1].append(s)

    def text(self, x, y, s, size=10, bold=False, gray=0.0):
        """y is measured from the top of the page."""
        self._op(f'BT {gray:.2f} g /{"F2" if bold else "F1"} {size} Tf {x:.1f} {self.h - y:.1f} Td ({_esc(s)}) Tj ET')

    def rect(self, x, y, w, h, gray=0.9, rgb=None):
        fill = f'{rgb[0]:.3f} {rgb[1]:.3f} {rgb[2]:.3f} rg' if rgb else f'{gray:.2f} g'
        self._op(f'{fill} {x:.1f} {self.h - y - h:.1f} {w:.1f} {h:.1f} re f')

    def line(self, x1, y1, x2, y2, gray=0.7, width=0.5):
        self._op(f'{gray:.2f} G {width} w {x1:.1f} {self.h - y1:.1f} m {x2:.1f} {self.h - y2:.1f} l S')

    def output(self):
        objects = []

        def add(body):
            objects.append(body)
            return len(objects)

        font1 = add(b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /WinAnsiEncoding >>')
        font2 = add(b'<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica-Bold /Encoding /WinAnsiEncoding >>')
        pages_id = len(objects) + 1 + 2 * len(self.pages)    # placeholder, fixed below
        page_ids = []
        for ops in self.pages:
            stream = zlib.compress('\n'.join(ops).encode('latin-1', 'replace'))
            content = add(b'<< /Length %d /Filter /FlateDecode >>\nstream\n' % len(stream) + stream + b'\nendstream')
            page_ids.append(add(None))
            objects[page_ids[-1] - 1] = (content,)
        pages_id = add(None)
        for pid in page_ids:
            content = objects[pid - 1][0]
            objects[pid - 1] = (f'<< /Type /Page /Parent {pages_id} 0 R /MediaBox [0 0 {self.w} {self.h}] '
                                f'/Resources << /Font << /F1 {font1} 0 R /F2 {font2} 0 R >> >> '
                                f'/Contents {content} 0 R >>').encode()
        objects[pages_id - 1] = (f'<< /Type /Pages /Kids [{" ".join(f"{p} 0 R" for p in page_ids)}] '
                                 f'/Count {len(page_ids)} >>').encode()
        catalog = add(f'<< /Type /Catalog /Pages {pages_id} 0 R >>'.encode())
        out = bytearray(b'%PDF-1.4\n%\xe2\xe3\xcf\xd3\n')
        offsets = []
        for i, body in enumerate(objects, 1):
            offsets.append(len(out))
            out += f'{i} 0 obj\n'.encode() + body + b'\nendobj\n'
        xref = len(out)
        out += f'xref\n0 {len(objects) + 1}\n0000000000 65535 f \n'.encode()
        out += b''.join(f'{o:010d} 00000 n \n'.encode() for o in offsets)
        out += f'trailer\n<< /Size {len(objects) + 1} /Root {catalog} 0 R >>\nstartxref\n{xref}\n%%EOF\n'.encode()
        return bytes(out)
