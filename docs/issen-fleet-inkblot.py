#!/usr/bin/env python3
"""Generate docs/issen-fleet-inkblot.png — an additive stacked symmetric
streamgraph of commit activity across the issen forensics fleet.

Documentation support script. It is self-contained: it reads each commit's
timestamp (`git log`, committer dates, HEAD) straight from the sibling fleet
repos under ~/src, bins the commits hourly, Gaussian-smooths each repo's series,
and stacks the bands about a symmetric centerline (matplotlib `baseline="sym"`).
Total stream thickness at any moment is the whole fleet's hourly commit rate; the
busiest repo straddles the centerline (inside-out band order) to minimise wiggle.

Usage:
    python3 docs/issen-fleet-inkblot.py
    ISSEN_FLEET_SRC=/path/to/src python3 docs/issen-fleet-inkblot.py  # custom root

Requires: matplotlib, numpy, and the fleet repos checked out as siblings of
`issen` under the same parent dir (e.g. ~/src/<repo>). Repos that are absent are
skipped with a warning, so the chart still renders on a partial checkout.
"""

import collections
import datetime as dt
import os
import subprocess
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.dates as mdates
import matplotlib.pyplot as plt
import numpy as np
from matplotlib.patches import Patch

# The issen "sphere" — issen plus the forensic libraries it orchestrates.
REPOS = [
    "issen", "memory-forensic", "forensicnomicon", "sqlite-forensic",
    "iso9660-forensic", "srum-forensic", "winevt-forensic", "browser-forensic",
    "vmdk-forensic", "ntfs-forensic", "usnjrnl-forensic", "winreg-forensic",
    "disk-forensic",
    "gpt-partition-forensic", "vhdx-forensic", "qcow2-forensic",
    "apm-partition-forensic", "mbr-partition-forensic", "ewf", "lnk-forensic",
    "segb-forensic", "trash-forensic", "useract-forensic", "prefetch-forensic",
    "shellhist-forensic", "snss-forensic", "peripheral-forensic", "cfb-forensic",
    "shellitem", "dmg", "lzo", "livedisk-forensic", "shrinkpath", "xpress-huffman",
]

SIGMA_HOURS = 8.0  # Gaussian smoothing of the hourly series (organic stream)

SCRIPT_DIR = Path(__file__).resolve().parent          # .../issen/docs
# Normally the fleet repos are siblings of `issen` under ~/src (two dirs up from
# this script). Allow an override so the script also runs from a worktree or CI.
SRC_ROOT = Path(os.environ.get(
    "ISSEN_FLEET_SRC", Path(__file__).resolve().parents[2])).expanduser()
OUT = SCRIPT_DIR / "issen-fleet-inkblot.png"


def commit_times(repo_path):
    """Yield a naive local datetime for every HEAD commit (committer date, tz
    stripped — local wall-clock hour). Each commit is one event of weight 1.
    """
    try:
        res = subprocess.run(
            ["git", "-C", str(repo_path), "log", "--pretty=format:%cI"],
            capture_output=True, text=True, check=True)
    except (subprocess.CalledProcessError, FileNotFoundError):
        return
    for line in res.stdout.splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            # strip tz (commits are dominantly +08); keep local wall-clock hour
            yield dt.datetime.fromisoformat(line).replace(tzinfo=None)
        except ValueError:
            pass


# ---- gather -----------------------------------------------------------------
events = []
for repo in REPOS:
    times = list(commit_times(SRC_ROOT / repo))
    if not times:
        print(f"  warning: no commits found for {repo} (skipping)")
        continue
    events.extend((t, repo, 1) for t in times)

if not events:
    raise SystemExit(f"No commits gathered from any repo under {SRC_ROOT}")

total_commits = len(events)
repo_totals = collections.Counter()
for _, repo, c in events:
    repo_totals[repo] += c
first = min(t for t, _, _ in events).replace(minute=0, second=0, microsecond=0)
last = max(t for t, _, _ in events)
n_hours = int((last - first).total_seconds() // 3600) + 1
x = np.array([first + dt.timedelta(hours=i) for i in range(n_hours)])

repos = [r for r, _ in repo_totals.most_common()]  # busiest first
counts = {r: np.zeros(n_hours) for r in repos}
for t, repo, c in events:
    counts[repo][int((t - first).total_seconds() // 3600)] += c

half = int(SIGMA_HOURS * 4)
k = np.arange(-half, half + 1)
kernel = np.exp(-(k ** 2) / (2 * SIGMA_HOURS ** 2))
kernel /= kernel.sum()
smooth = {r: np.convolve(counts[r], kernel, mode="same") for r in repos}

total_series = np.sum([smooth[r] for r in repos], axis=0)  # fleet commits/hour
total_peak = total_series.max()
di = int(np.argmax(total_series))

# inside-out band order: busiest straddles the centre, rest alternate outward
order = []
for i, r in enumerate(repos):
    (order.append if i % 2 == 0 else (lambda v: order.insert(0, v)))(r)

cmap = plt.get_cmap("turbo")
n = len(repos)
color_of = {r: cmap(0.04 + 0.92 * i / max(1, n - 1)) for i, r in enumerate(repos)}


def nice_step(peak):
    raw = peak / 4.0
    if raw <= 0:
        return 1
    mag = 10 ** np.floor(np.log10(raw))      # power-of-ten magnitude
    for m in (1, 2, 2.5, 5, 10):             # 1-2-2.5-5 ladder at that magnitude
        if m * mag >= raw:
            return m * mag
    return 10 * mag


# ---- draw -------------------------------------------------------------------
fig, ax = plt.subplots(figsize=(16, 8))
fig.patch.set_facecolor("#0d1117")
ax.set_facecolor("#0d1117")

ax.stackplot(x, *[smooth[r] for r in order], colors=[color_of[r] for r in order],
             baseline="sym", linewidth=0.0, alpha=0.95)

lim = total_peak / 2 * 1.12
ax.set_ylim(-lim, lim)
# magnitude markers = TOTAL commits/hour: gridline pair at +/-(M/2) labelled M
step = nice_step(total_peak)
mags, m = [], step
while m / 2 <= lim:
    mags.append(m)
    m += step
positions = [-q / 2 for q in reversed(mags)] + [0] + [q / 2 for q in mags]
labels = [f"{q:g}" for q in reversed(mags)] + ["0"] + [f"{q:g}" for q in mags]
ax.set_yticks(positions)
ax.set_yticklabels(labels)
ax.set_ylabel("fleet commits / hour (stacked total)", color="#8b949e", fontsize=10)
for s in ("top", "right"):
    ax.spines[s].set_visible(False)
ax.spines["left"].set_color("#30363d")
ax.spines["bottom"].set_color("#30363d")
ax.tick_params(axis="x", colors="#8b949e")
ax.tick_params(axis="y", colors="#8b949e", labelsize=8, length=3)
for q in mags:
    ax.axhline(q / 2, color="#30363d", lw=0.4, alpha=0.5, zorder=5)
    ax.axhline(-q / 2, color="#30363d", lw=0.4, alpha=0.5, zorder=5)
ax.xaxis.set_major_locator(mdates.WeekdayLocator(byweekday=0, interval=2))
ax.xaxis.set_major_formatter(mdates.DateFormatter("%b %d"))
ax.margins(x=0.01)

# single-row (one entry per line) legend down the right edge, busiest first
handles = [Patch(facecolor=color_of[r], edgecolor="none",
                 label=f"{r}  ({repo_totals[r]:,})") for r in repos]
leg = ax.legend(handles=handles, loc="center left", bbox_to_anchor=(1.005, 0.5),
                ncol=1, fontsize=6.4, framealpha=0.0, labelcolor="#c9d1d9",
                handlelength=1.0, handleheight=1.0, labelspacing=0.28,
                title="repo (commits) — busiest first", title_fontsize=7.5)
leg.get_title().set_color("#8b949e")

fig.text(0.5, 0.965, "issen forensics fleet — commit activity inkblot",
         ha="center", fontsize=16, fontweight="bold", color="#f0f6fc")
fig.text(0.5, 0.938,
         "additive stacked streamgraph (symmetric) · total thickness = fleet "
         "commits/hour · busiest band centered",
         ha="center", fontsize=9, color="#8b949e")

cap = (f"{len(repos)} repos · {total_commits:,} commits · "
       f"{first.date().isoformat()} → {last.date().isoformat()} · "
       f"Gaussian-smoothed hourly commit rate (sigma={SIGMA_HOURS:g}h) · "
       f"fleet peak ~{total_peak:,.1f}/h around {x[di].strftime('%b %d %H:%M')}")
fig.text(0.99, 0.012, cap, ha="right", fontsize=8, color="#6e7681")

plt.tight_layout(rect=(0.0, 0.02, 0.89, 0.92))
plt.savefig(OUT, dpi=140, facecolor=fig.get_facecolor())
print("wrote", OUT)
print(f"repos={len(repos)} commits={total_commits} hours={n_hours} "
      f"total_peak={total_peak:,.1f}/h peak_at={x[di]}")
