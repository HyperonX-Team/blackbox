"""DataSift - a BLACKBOX appliance for CSV cleaning and exploration.

Load a CSV (from ./input or by uploading), inspect columns and missing
values, filter rows, get statistics, and export a cleaned CSV to ./output.

Pure Python standard library: no third-party dependencies, nothing to pip.
Serves a local web UI on 127.0.0.1 only.
"""

import argparse
import csv
import html
import io
import json
import os
import statistics
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlparse, parse_qs

LOCK = threading.Lock()
DATA = {"rows": [], "cols": [], "source": None, "filters": [], "original": []}

PAGE = """<!DOCTYPE html><html><head><meta charset="utf-8"><title>DataSift - BLACKBOX</title>
<style>
 body{background:#0a0a0f;color:#d8f3d8;font-family:ui-monospace,Consolas,monospace;margin:0;padding:24px}
 h1{color:#7CFC90;font-size:20px} small{color:#5b7a5f}
 .panel{background:#10131a;border:1px solid #223;border-radius:8px;padding:14px;margin:12px 0}
 table{border-collapse:collapse;width:100%;font-size:12px}
 th,td{border:1px solid #223;padding:4px 8px;text-align:left;white-space:nowrap;max-width:220px;overflow:hidden}
 th{color:#7CFC90} select,input,button{background:#0a0a0f;color:#d8f3d8;border:1px solid #2c5a2f;border-radius:4px;padding:6px}
 button{cursor:pointer} .muted{color:#5b7a5f} .bad{color:#ff7b72} .kpi{display:inline-block;margin-right:24px}
 kbd{background:#223;border-radius:3px;padding:1px 5px}
</style></head><body>
<h1>DATA<b>SIFT</b> <small>· a BLACKBOX appliance · download a machine</small></h1>
<div class="panel"><b>Source</b><br><br>
 <select id="file"></select> <button onclick="loadFile()">Load</button>
 &nbsp; or upload: <input type="file" id="up" accept=".csv,.txt">
 <button onclick="upload()">Upload</button>
 <span class="muted" id="srcinfo"></span></div>
<div class="panel"><b>Columns</b><div id="cols"></div></div>
<div class="panel"><b>Filter</b>
 <select id="fcol"></select><select id="fop">
  <option value="gt">&gt;</option><option value="lt">&lt;</option>
  <option value="eq">=</option><option value="contains">contains</option>
  <option value="notmissing">is present</option><option value="missing">is missing</option>
 </select><input id="fval" placeholder="value"> <button onclick="addFilter()">Apply</button>
 <button onclick="resetFilters()">Reset</button><div id="active" class="muted"></div></div>
<div class="panel"><b>Rows</b> <span id="count" class="muted"></span>
 <button style="float:right" onclick="exportData()">Export cleaned CSV → output/clean.csv</button>
 <div style="clear:both"></div><div id="preview"></div></div>
<div class="panel"><b>Statistics</b><div id="stats"></div></div>
<script>
async function api(p,opt){const r=await fetch(p,opt);if(!r.ok)throw new Error(await r.text());return r.json()}
function h(s){const d=document.createElement('div');d.textContent=s;return d.innerHTML}
async function refreshFiles(){const j=await api('/api/files');
 document.getElementById('file').innerHTML=j.files.map(f=>`<option>${f}</option>`).join('')||'<option value="">(no files in input/)</option>'}
async function loadFile(){const name=document.getElementById('file').value;
 try{const j=await api('/api/load',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({name})});render(j)}catch(e){alert(e)}}
async function upload(){const f=document.getElementById('up').files[0];if(!f)return alert('Choose a file');
 const buf=await f.text();const j=await api('/api/load',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({text:buf,name:f.name})});render(j)}
function render(j){document.getElementById('srcinfo').textContent=' - '+j.source+' · '+j.total+' rows · '+j.cols.length+' columns';
 document.getElementById('cols').innerHTML='<br><table><tr><th>column</th><th>type</th><th>missing</th><th>unique</th><th>min length</th></tr>'+
 j.cols.map(c=>`<tr><td>${h(c.name)}</td><td>${c.type}</td><td class="${c.missing?'bad':''}">${c.missing}</td><td>${c.unique}</td><td>${c.minlen}</td></tr>`).join('')+'</table>';
 document.getElementById('fcol').innerHTML=j.cols.map(c=>`<option>${h(c.name)}</option>`).join('');
 renderStats(j.stats)}
function renderStats(stats){document.getElementById('stats').innerHTML='<br>'+Object.entries(stats).map(([k,v])=>
 `<span class="kpi"><b>${h(k)}</b> n=${v.count} mean=${v.mean} median=${v.median} std=${v.std} min=${v.min} q1=${v.q1} q3=${v.q3} max=${v.max}</span>`).join('<br>')||'<span class=muted>no numeric columns</span>'}
async function refreshData(){const j=await api('/api/preview');
 document.getElementById('count').textContent=j.filtered+' of '+j.total+' rows';
 document.getElementById('active').innerHTML='active filters: '+(j.filters.map((f,i)=>`${h(f.column)} ${f.op} ${h(f.value||'')} <a href='#' onclick='dropFilter(${i});return false'>[x]</a>`).join(' · ')||'none');
 const rows=j.rows.slice(0,60);
 document.getElementById('preview').innerHTML=rows.length?'<br><table><tr>'+j.cols.map(c=>`<th>${h(c)}</th>`).join('')+'</tr>'+
  rows.map(r=>'<tr>'+j.cols.map(c=>`<td>${h(r[c]??'')}</td>`).join('')+'</tr>').join('')+'</table>':'<p class=muted>no rows match</p>';
 renderStats(j.stats)}
async function addFilter(){const c=document.getElementById('fcol').value,o=document.getElementById('fop').value,v=document.getElementById('fval').value;
 await api('/api/filter',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({add:{column:c,op:o,value:v}})});refreshData()}
async function dropFilter(i){await api('/api/filter',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({drop:i})});refreshData()}
async function resetFilters(){await api('/api/reset',{method:'POST'});refreshData()}
async function exportData(){const j=await api('/api/export',{method:'POST'});alert('Wrote '+j.path)}
refreshFiles();refreshData();
</script></body></html>"""


def sniff(values):
    vals = [v for v in values if v != ""]
    if not vals:
        return "empty"
    if all(v.strip().lower() in ("true", "false") for v in vals):
        return "bool"
    def isnum(v):
        try:
            float(v)
            return True
        except ValueError:
            return False
    if all(isnum(v) for v in vals):
        return "number"
    return "text"


def coerce(v):
    try:
        f = float(v)
        return f
    except (TypeError, ValueError):
        return None


def numeric_stats(values):
    v = sorted(x for x in (coerce(t) for t in values) if x is not None)
    if not v:
        return None
    def q(p):
        if len(v) == 1:
            return v[0]
        idx = p * (len(v) - 1)
        lo, hi = int(idx), min(int(idx) + 1, len(v) - 1)
        return v[lo] + (v[hi] - v[lo]) * (idx - lo)
    return {
        "count": len(v),
        "mean": round(statistics.fmean(v), 4),
        "median": round(statistics.median(v), 4),
        "std": round(statistics.pstdev(v), 4) if len(v) > 1 else 0.0,
        "min": v[0], "q1": round(q(0.25), 4), "q3": round(q(0.75), 4), "max": v[-1],
    }


def column_report():
    cols = []
    for c in DATA["cols"]:
        vals = [r.get(c, "") for r in DATA["original"]]
        present = [v for v in vals if v != ""]
        cols.append({
            "name": c,
            "type": sniff(vals),
            "missing": len(vals) - len(present),
            "unique": len(set(present)),
            "minlen": min((len(v) for v in present), default=0),
        })
    return cols


def current_rows():
    rows = DATA["original"]
    for f in DATA["filters"]:
        col, op, val = f["column"], f["op"], f.get("value", "")
        out = []
        for r in rows:
            cell = r.get(col, "")
            try:
                if op == "missing":
                    keep = cell == ""
                elif op == "notmissing":
                    keep = cell != ""
                elif op == "contains":
                    keep = val.lower() in cell.lower()
                elif op == "eq":
                    keep = cell == val
                elif cell == "":
                    keep = False
                else:
                    a, b = coerce(cell), coerce(val)
                    if a is None or b is None:
                        keep = (cell > val) if op == "gt" else (cell < val)
                    else:
                        keep = a > b if op == "gt" else a < b
            except (TypeError, ValueError):
                keep = False
            if keep:
                out.append(r)
        rows = out
    return rows


def stats_report():
    return {c: s for c in DATA["cols"]
            for s in [numeric_stats([r.get(c, "") for r in current_rows()])] if s}


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *a):
        pass

    def _json(self, obj, code=200):
        body = json.dumps(obj).encode()
        self.send_response(code)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _body(self):
        n = int(self.headers.get("Content-Length", 0))
        return json.loads(self.rfile.read(n) or b"{}")

    def do_GET(self):
        u = urlparse(self.path)
        if u.path == "/":
            self._json({"error": "use browser"}) if "json" in self.headers.get("Accept", "") else self._page()
        elif u.path == "/api/files":
            indir = os.environ.get("BLACKBOX_INPUT", os.path.join(os.getcwd(), "input"))
            try:
                files = sorted(f for f in os.listdir(indir) if f.lower().endswith((".csv", ".txt")))
            except OSError:
                files = []
            here = os.path.dirname(os.path.abspath(__file__))
            files += sorted(f for f in os.listdir(here) if f.endswith(".csv"))
            self._json({"files": files})
        elif u.path == "/api/preview":
            with LOCK:
                rows = current_rows()
                self._json({"cols": DATA["cols"], "rows": rows[:400], "total": len(DATA["original"]),
                            "filtered": len(rows), "filters": DATA["filters"], "stats": stats_report()})
        else:
            self.send_error(404)

    def _page(self):
        body = PAGE.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_POST(self):
        u = urlparse(self.path)
        try:
            if u.path == "/api/load":
                b = self._body()
                text = b.get("text")
                if text is None:
                    want = os.path.basename(b.get("name", ""))
                    indir = os.environ.get("BLACKBOX_INPUT", os.path.join(os.getcwd(), "input"))
                    path = os.path.join(indir, want)
                    if not os.path.isfile(path):
                        bundled = os.path.join(os.path.dirname(os.path.abspath(__file__)), want)
                        path = bundled if os.path.isfile(bundled) else path
                    if not os.path.isfile(path):
                        return self._json({"error": f"no such file in input/: {b.get('name')}"}, 400)
                    text = open(path, encoding="utf-8-sig", newline="").read()
                    name = os.path.basename(path)
                else:
                    name = b.get("name", "upload.csv")
                rd = csv.DictReader(io.StringIO(text))
                rows = [{k: (v if v is not None else "") for k, v in r.items()} for r in rd]
                with LOCK:
                    DATA["cols"] = [c for c in (rd.fieldnames or []) if c is not None]
                    DATA["original"] = rows
                    DATA["filters"] = []
                    DATA["source"] = name
                self._json({"ok": True, "source": name, "total": len(rows),
                            "cols": column_report(), "stats": stats_report()})
            elif u.path == "/api/filter":
                b = self._body()
                with LOCK:
                    if "add" in b:
                        DATA["filters"].append(b["add"])
                    if "drop" in b:
                        DATA["filters"].pop(int(b["drop"]), None)
                self._json({"ok": True})
            elif u.path == "/api/reset":
                with LOCK:
                    DATA["filters"] = []
                self._json({"ok": True})
            elif u.path == "/api/export":
                with LOCK:
                    rows, cols = current_rows(), DATA["cols"]
                    outdir = os.environ.get("BLACKBOX_OUTPUT", os.path.join(os.getcwd(), "output"))
                    os.makedirs(outdir, exist_ok=True)
                    path = os.path.join(outdir, "clean.csv")
                    with open(path, "w", newline="", encoding="utf-8") as f:
                        w = csv.DictWriter(f, fieldnames=cols)
                        w.writeheader()
                        w.writerows(rows)
                self._json({"ok": True, "path": path})
            else:
                self.send_error(404)
        except Exception as e:
            self._json({"error": f"{type(e).__name__}: {e}"}, 500)


def main():
    ap = argparse.ArgumentParser(description="DataSift BLACKBOX appliance")
    ap.add_argument("--port", type=int, default=int(os.environ.get("BLACKBOX_PORT", "8765")))
    args = ap.parse_args()
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    print(f"DataSift is serving http://127.0.0.1:{args.port}")
    print(f"  input dir:  {os.environ.get('BLACKBOX_INPUT', os.getcwd() + '/input')}")
    print(f"  output dir: {os.environ.get('BLACKBOX_OUTPUT', os.getcwd() + '/output')}")
    print("  (drop CSV files into input/, then open the URL in your browser; Ctrl+C stops)")
    sys.stdout.flush()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        pass


if __name__ == "__main__":
    main()
