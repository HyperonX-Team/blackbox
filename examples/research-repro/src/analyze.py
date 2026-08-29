"""research-repro: a sealed research environment.

Reads input/data.csv (falls back to the bundled sample dataset), runs a
deterministic analysis, and writes:

    output/metrics.json      machine-readable results
    output/report.html       human report rendered with Jinja2 (locked dep)
    output/figures/*.svg     charts drawn with the standard library

The exact environment - interpreter 3.12.x, Jinja2 3.1.4, MarkupSafe pinned
by hash - travels inside the .blackbox. The recipient runs the same analysis
with the same bytes of every dependency.
"""

import csv
import json
import math
import os
import statistics
import sys

from jinja2 import Template

HERE = os.path.dirname(os.path.abspath(__file__))


def load_rows():
    indir = os.environ.get("BLACKBOX_INPUT", os.path.join(os.getcwd(), "input"))
    path = os.path.join(indir, "data.csv")
    if not os.path.isfile(path):
        path = os.path.join(HERE, "sample_data.csv")
    with open(path, newline="", encoding="utf-8-sig") as f:
        return list(csv.DictReader(f)), os.path.basename(path)


def num(rows, col):
    out = []
    for r in rows:
        v = r.get(col, "").strip()
        if v == "":
            continue
        try:
            out.append(float(v))
        except ValueError:
            pass
    return out


def ols(xs, ys):
    n = len(xs)
    if n < 3:
        return None
    mx, my = sum(xs) / n, sum(ys) / n
    sxx = sum((x - mx) ** 2 for x in xs)
    sxy = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    if sxx == 0:
        return None
    slope = sxy / sxx
    intercept = my - slope * mx
    resid = [y - (intercept + slope * x) for x, y in zip(xs, ys)]
    sse = sum(r * r for r in resid)
    sst = sum((y - my) ** 2 for y in ys)
    r2 = 1 - sse / sst if sst else 0.0
    return {"slope": slope, "intercept": intercept, "r_squared": r2, "n": n}


def pearson(xs, ys):
    n = min(len(xs), len(ys))
    xs, ys = xs[:n], ys[:n]
    if n < 3:
        return None
    mx, my = sum(xs) / n, sum(ys) / n
    num_ = sum((x - mx) * (y - my) for x, y in zip(xs, ys))
    den = math.sqrt(sum((x - mx) ** 2 for x in xs) * sum((y - my) ** 2 for y in ys))
    return num_ / den if den else None


def svg_line_chart(series, path, title):
    w, h, pad = 640, 320, 40
    ys = [v for s in series for v in s["points"]]
    if not ys:
        return
    lo, hi = min(ys), max(ys)
    hi = hi if hi > lo else lo + 1

    def sx(i, n):
        return pad + (w - 2 * pad) * i / max(n - 1, 1)

    def sy(v):
        return h - pad - (h - 2 * pad) * (v - lo) / (hi - lo)

    colors = ["#4ade80", "#60a5fa", "#f472b6", "#facc15", "#a78bfa"]
    parts = [f'<svg xmlns="http://www.w3.org/2000/svg" width="{w}" height="{h}" font-family="monospace">',
             f'<rect width="{w}" height="{h}" fill="#0b0e14"/>',
             f'<text x="{pad}" y="24" fill="#d8f3d8" font-size="14">{title}</text>',
             f'<line x1="{pad}" y1="{h-pad}" x2="{w-pad}" y2="{h-pad}" stroke="#333"/>']
    for k, s in enumerate(series):
        pts = " ".join(f"{sx(i, len(s['points'])):.1f},{sy(v):.1f}" for i, v in enumerate(s["points"]))
        parts.append(f'<polyline points="{pts}" fill="none" stroke="{colors[k % len(colors)]}" stroke-width="2"/>')
        parts.append(f'<text x="{pad + 8}" y="{40 + k * 18}" fill="{colors[k % len(colors)]}" font-size="11">{s["name"]}</text>')
    parts.append(f'<text x="{pad}" y="{h - 12}" fill="#667" font-size="10">n={max((len(s["points"]) for s in series), default=0)}  range=[{lo:g}, {hi:g}]</text>')
    parts.append("</svg>")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(parts))


def main():
    rows, source = load_rows()
    outdir = os.environ.get("BLACKBOX_OUTPUT", os.path.join(os.getcwd(), "output"))
    os.makedirs(outdir, exist_ok=True)
    figdir = os.path.join(outdir, "figures")
    os.makedirs(figdir, exist_ok=True)

    cols = [c for c in (rows[0].keys() if rows else []) if c]
    numeric = {c: num(rows, c) for c in cols}
    numeric = {c: v for c, v in numeric.items() if v and len(v) == len(rows)}

    metrics = {"dataset": source, "rows": len(rows), "analysis": os.environ.get("ANALYSIS_NAME", "v1"),
               "columns": {}, "by_city": {}, "model": None, "correlation": None}
    for c, v in numeric.items():
        metrics["columns"][c] = {
            "mean": statistics.fmean(v), "median": statistics.median(v),
            "std": statistics.stdev(v) if len(v) > 1 else 0.0,
            "min": min(v), "max": max(v), "missing": len(rows) - len(v),
        }
    if "city" in (rows[0] if rows else {}):
        for city in sorted({r["city"] for r in rows}):
            sub = [r for r in rows if r.get("city") == city]
            t = num(sub, "temperature_c")
            if t:
                metrics["by_city"][city] = {"n": len(sub), "mean_temperature_c": statistics.fmean(t)}
    x = list(range(1, len(rows) + 1))
    temp = numeric.get("temperature_c")
    if temp:
        metrics["model"] = ols(x, temp)
        if "humidity" in numeric and len(numeric["humidity"]) == len(temp):
            metrics["correlation"] = {"temperature_c__humidity": pearson(temp, numeric["humidity"])}
        svg_line_chart([{"name": "temperature_c", "points": temp}], os.path.join(figdir, "temperature.svg"),
                       "temperature_c over time (input order)")
    hum = numeric.get("humidity")
    if hum:
        svg_line_chart([{"name": "humidity", "points": hum}], os.path.join(figdir, "humidity.svg"),
                       "humidity over time (input order)")

    with open(os.path.join(outdir, "metrics.json"), "w", encoding="utf-8") as f:
        json.dump(metrics, f, indent=2, sort_keys=True)

    with open(os.path.join(HERE, "report.html.j2"), encoding="utf-8") as f:
        tmpl = Template(f.read())
    env_info = {"python": sys.version.split()[0], "executable": sys.executable}
    import jinja2
    env_info["jinja2"] = jinja2.__version__
    report = tmpl.render(metrics=metrics, env=env_info,
                         figures=["figures/" + fn for fn in sorted(os.listdir(figdir))])
    with open(os.path.join(outdir, "report.html"), "w", encoding="utf-8") as f:
        f.write(report)

    print(f"research-repro: analyzed {len(rows)} rows from {source}")
    print(f"  wrote: {os.path.join(outdir, 'report.html')}")
    print(f"  wrote: {os.path.join(outdir, 'metrics.json')}")
    print(f"  wrote: {os.path.join(figdir, '*')} ({len(os.listdir(figdir))} figures)")


if __name__ == "__main__":
    main()
