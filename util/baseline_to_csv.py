import csv
import re
from pathlib import Path

LOG = Path("audit.log")
out = Path("baseline_timeseries.csv")

line_re = re.compile(
    r"^\[(?P<ts>[^\]]+)\]\s+BASELINE_RECALC GLOBAL \| (?P<src>[^|]+)\| (?P<rate>[^|]+)\| (?P<mean>[^\|]+)\|(?P<std>[^\|]+)\s*\|\s*(?P<win>\d+)s"
)

with LOG.open(encoding="utf-8", errors="replace") as f, out.open("w", newline="", encoding="utf-8") as w:
    wr = csv.writer(w)
    wr.writerow(["ts_utc", "source", "rate_full_window", "effective_mean", "effective_std", "window_s"])
    for raw in f:
        if "BASELINE_RECALC" not in raw:
            continue
        m = line_re.match(raw.strip())
        if not m:
            continue
        wr.writerow(
            [
                m["ts"].strip(),
                m["src"].strip(),
                m["rate"].strip(),
                m["mean"].strip(),
                m["std"].strip(),
                m["win"].strip(),
            ]
        )

print("Wrote", out.resolve())