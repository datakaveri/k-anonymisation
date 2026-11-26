"""A minimal .xlsx writer and reader on the standard library, for the join corpus.

Only what the corpus needs: sheets of text cells (inline strings, so nothing is ever turned into a
number or a date), and reading the same back, including the shared-string workbooks SKALD itself writes.
No styles, no formulas. Not for general use.
"""
import re
import zipfile
from xml.etree import ElementTree as ET
from xml.sax.saxutils import escape

NS = {"m": "http://schemas.openxmlformats.org/spreadsheetml/2006/main",
      "r": "http://schemas.openxmlformats.org/officeDocument/2006/relationships",
      "p": "http://schemas.openxmlformats.org/package/2006/relationships"}


def _col(i):
    s = ""
    i += 1
    while i:
        i, r = divmod(i - 1, 26)
        s = chr(65 + r) + s
    return s


def write_xlsx(path, sheets):
    """sheets: [(name, [[cell, ...], ...])], first row the header. Empty strings are left blank."""
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as z:
        z.writestr("[Content_Types].xml",
                   '<?xml version="1.0" encoding="UTF-8"?><Types xmlns="http://schemas.openxmlformats.org/package/2006/content-types">'
                   '<Default Extension="rels" ContentType="application/vnd.openxmlformats-package.relationships+xml"/>'
                   '<Default Extension="xml" ContentType="application/xml"/>'
                   '<Override PartName="/xl/workbook.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.sheet.main+xml"/>'
                   + "".join(f'<Override PartName="/xl/worksheets/sheet{i + 1}.xml" ContentType="application/vnd.openxmlformats-officedocument.spreadsheetml.worksheet+xml"/>'
                             for i in range(len(sheets))) + "</Types>")
        z.writestr("_rels/.rels",
                   '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   '<Relationship Id="rId1" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/officeDocument" Target="xl/workbook.xml"/></Relationships>')
        z.writestr("xl/workbook.xml",
                   '<?xml version="1.0" encoding="UTF-8"?><workbook xmlns="%s" xmlns:r="%s"><sheets>' % (NS["m"], NS["r"])
                   + "".join(f'<sheet name="{escape(n)}" sheetId="{i + 1}" r:id="rId{i + 1}"/>' for i, (n, _) in enumerate(sheets))
                   + "</sheets></workbook>")
        z.writestr("xl/_rels/workbook.xml.rels",
                   '<?xml version="1.0" encoding="UTF-8"?><Relationships xmlns="http://schemas.openxmlformats.org/package/2006/relationships">'
                   + "".join(f'<Relationship Id="rId{i + 1}" Type="http://schemas.openxmlformats.org/officeDocument/2006/relationships/worksheet" Target="worksheets/sheet{i + 1}.xml"/>'
                             for i in range(len(sheets))) + "</Relationships>")
        for i, (_, rows) in enumerate(sheets):
            body = []
            for r, row in enumerate(rows):
                cells = "".join(f'<c r="{_col(c)}{r + 1}" t="inlineStr"><is><t xml:space="preserve">{escape(v)}</t></is></c>'
                                for c, v in enumerate(row) if v != "")
                body.append(f'<row r="{r + 1}">{cells}</row>')
            z.writestr(f"xl/worksheets/sheet{i + 1}.xml",
                       f'<?xml version="1.0" encoding="UTF-8"?><worksheet xmlns="{NS["m"]}"><sheetData>{"".join(body)}</sheetData></worksheet>')


def read_xlsx(path):
    """[(sheet name, rows)] with every cell as text and short rows padded to the widest."""
    with zipfile.ZipFile(path) as z:
        shared = []
        if "xl/sharedStrings.xml" in z.namelist():
            for si in ET.fromstring(z.read("xl/sharedStrings.xml")).findall("m:si", NS):
                shared.append("".join(t.text or "" for t in si.iter(f'{{{NS["m"]}}}t')))
        rels = {r.get("Id"): r.get("Target") for r in ET.fromstring(z.read("xl/_rels/workbook.xml.rels")).findall("p:Relationship", NS)}
        out = []
        for sh in ET.fromstring(z.read("xl/workbook.xml")).find("m:sheets", NS):
            target = rels[sh.get(f'{{{NS["r"]}}}id')].lstrip("/")
            target = target if target.startswith("xl/") else "xl/" + target
            rows = []
            for row in ET.fromstring(z.read(target)).find("m:sheetData", NS):
                # A row with no cell is not written at all (SKALD writes no cell for an empty
                # string); it still takes its place, as it does when calamine reads the range.
                while len(rows) + 1 < int(row.get("r", len(rows) + 1)):
                    rows.append([])
                cells = {}
                for c in row:
                    idx = 0
                    for ch in re.match(r"[A-Z]+", c.get("r")).group():
                        idx = idx * 26 + ord(ch) - 64
                    t = c.get("t")
                    if t == "inlineStr":
                        v = "".join(x.text or "" for x in c.iter(f'{{{NS["m"]}}}t'))
                    else:
                        raw = c.find("m:v", NS)
                        v = "" if raw is None else (shared[int(raw.text)] if t == "s" else raw.text)
                    cells[idx - 1] = v
                rows.append([cells.get(i, "") for i in range(max(cells) + 1)] if cells else [])
            width = max((len(r) for r in rows), default=0)
            out.append((sh.get("name"), [r + [""] * (width - len(r)) for r in rows]))
        return out
