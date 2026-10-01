"""Drawing helpers for the live view: the race-track picture, the timing chart and the alarm feed."""
from __future__ import annotations

import altair as alt
import pandas as pd

SERIES = ("Box lap time", "Monitor delivery time")

# Validated categorical slots 1 and 2 (light, dark), and the fixed status palette.
_SERIES_COLORS = {False: ("#2a78d6", "#eb6834"), True: ("#3987e5", "#d95926")}
GOOD, WARNING, CRITICAL = "#0ca30c", "#fab219", "#d03b3b"

_INK = {
    False: {"primary": "#0b0b0b", "secondary": "#52514e", "muted": "#898781",
            "room": "#f7f7f5", "room_line": "#e1e0d9", "track": "#d6d5cf"},
    True: {"primary": "#ffffff", "secondary": "#c3c2b7", "muted": "#898781",
           "room": "#1a1a19", "room_line": "#2c2c2a", "track": "#383835"},
}

TAP_LABELS = {
    "delay": "Relay tap: +150 ms per frame",
    "drop": "Every 5th frame lost here",
    "alter": "Every 7th frame altered here",
}

# The fibre loop: out along the top lane, round the timing line in the monitoring room,
# back along the bottom lane, and round the sealed box in the vault room.
_LOOP = "M 210 75 L 600 75 A 50 50 0 0 1 600 175 L 210 175 A 50 50 0 0 1 210 75 Z"
_FRAMES = 8


def _status_line(x: int, y: int, color: str, text: str) -> str:
    """A status: a coloured dot with a text label beside it (the label carries the meaning, not the colour)."""
    return (f'<div class="dbx-status" style="left:{x}px;top:{y}px">'
            f'<span class="dbx-dot" style="background:{color}"></span>{text}</div>')


def track_html(*, dark: bool, running: bool, tap: str | None, box_state: str, vault_frozen: bool,
               canary_opened: bool, monitor_state: str, battery_bucket: int) -> str:
    """The loop between the two rooms, with frames lapping it.

    Built only from discrete state, so the HTML stays identical between refreshes
    and the animation keeps running smoothly until something actually changes.
    """
    ink = _INK[dark]
    frame_color = _SERIES_COLORS[dark][0]
    lap_s = 8.0 if tap == "delay" else 4.0
    frames_on_track = box_state in ("running", "stopped")

    frames = []
    for i in range(_FRAMES):
        color = frame_color
        style = ""
        if tap == "delay":
            color = WARNING
        elif tap == "drop" and i in (2, 6):
            style = "opacity:0;"
        elif tap == "alter" and i == 3:
            color = CRITICAL
        delay = -lap_s * i / _FRAMES
        frames.append(f'<div class="dbx-frame" style="background:{color};animation-delay:{delay:.2f}s;{style}"></div>')
    if not frames_on_track:
        frames = []

    if box_state == "running":
        box_line = (CRITICAL, "Vault frozen: ransomware pattern") if vault_frozen else (GOOD, "Box running")
    elif box_state == "shut down":
        box_line = (WARNING, "Clean shutdown (battery reserve)")
    elif box_state == "no power":
        box_line = (CRITICAL, "No power")
    else:
        box_line = (ink["muted"], "Run stopped")

    monitor_line = {
        "ok": (GOOD, "Every frame verified and on time"),
        "alarm": (CRITICAL, "Alarm raised"),
        "silent": (CRITICAL, "Silence: no frames arriving"),
        "announced": (WARNING, "Box announced its shutdown"),
    }[monitor_state]

    tap_html = ""
    if tap:
        tap_color = WARNING if tap == "delay" else CRITICAL
        tap_html = (f'<div class="dbx-tap" style="border-color:{tap_color}"></div>'
                    + _status_line(300, 36, tap_color, TAP_LABELS[tap]))

    battery_w = max(0, min(100, battery_bucket))
    battery_color = GOOD if battery_w > 30 else (WARNING if battery_w > 10 else CRITICAL)
    canary_html = _status_line(26, 212, CRITICAL, "Canary record opened") if canary_opened else ""

    # Plain HTML and CSS only: Streamlit's sanitiser strips inline SVG.
    return f"""
<style>
.dbx-wrap {{ overflow-x: auto; }}
.dbx-stage {{ position: relative; width: 760px; height: 248px; margin: 0 auto; color: {ink["primary"]};
              font-family: system-ui, -apple-system, "Segoe UI", sans-serif; font-size: 13px; }}
.dbx-stage div {{ position: absolute; box-sizing: border-box; }}
.dbx-room {{ top: 10px; width: 262px; height: 228px; border: 1px solid {ink["room_line"]};
             border-radius: 10px; background: {ink["room"]}; }}
.dbx-title {{ font-size: 14px; font-weight: 600; }}
.dbx-note {{ font-size: 11px; color: {ink["secondary"]}; white-space: nowrap; }}
.dbx-track {{ left: 151px; top: 66px; width: 508px; height: 118px; border: 18px solid {ink["track"]};
              border-radius: 59px; }}
.dbx-box {{ left: 30px; top: 92px; width: 112px; height: 54px; border: 1.5px solid {ink["secondary"]};
            border-radius: 8px; text-align: center; padding-top: 8px; line-height: 1.35; }}
.dbx-stage .dbx-box div, .dbx-stage .dbx-status span {{ position: static; }}
.dbx-bar {{ left: 30px; top: 154px; width: 112px; height: 8px; border-radius: 4px; background: {ink["track"]}; }}
.dbx-fill {{ left: 30px; top: 154px; height: 8px; border-radius: 4px; }}
.dbx-timing {{ left: 664px; top: 104px; width: 10px; height: 42px; border: 2px solid {ink["secondary"]};
               border-right: none; }}
.dbx-tap {{ left: 387px; top: 62px; width: 26px; height: 26px; border: 3px solid; border-radius: 50%; }}
.dbx-status {{ white-space: nowrap; display: flex; align-items: center; gap: 7px; }}
.dbx-dot {{ display: inline-block; width: 10px; height: 10px; border-radius: 50%; }}
.dbx-frame {{ left: 0; top: 0; width: 12px; height: 12px; border-radius: 50%;
              box-shadow: 0 0 0 2px {ink["track"]};
              offset-path: path("{_LOOP}"); offset-anchor: center; offset-rotate: 0deg;
              animation: dbx-lap {lap_s:.1f}s linear infinite;
              animation-play-state: {"running" if running else "paused"}; }}
@keyframes dbx-lap {{ from {{ offset-distance: 0%; }} to {{ offset-distance: 100%; }} }}
</style>
<div class="dbx-wrap"><div class="dbx-stage" role="img"
     aria-label="Fibre loop from the sealed box in the vault room to the monitoring room and back">
  <div class="dbx-room" style="left:8px"></div>
  <div class="dbx-room" style="left:490px"></div>
  <div class="dbx-title" style="left:24px;top:20px">Vault room</div>
  <div class="dbx-title" style="left:506px;top:20px">Monitoring room</div>
  <div class="dbx-note" style="left:506px;top:42px">passive tap: receive only</div>
  <div class="dbx-track"></div>
  <div class="dbx-note" style="left:290px;top:92px">frames out &rarr;</div>
  <div class="dbx-note" style="left:290px;top:142px">&larr; frames back</div>
  <div class="dbx-box"><div>Sealed box</div><div class="dbx-note">signs every frame</div></div>
  <div class="dbx-bar"></div>
  <div class="dbx-fill" style="width:{112 * battery_w / 100:.0f}px;background:{battery_color}"></div>
  <div class="dbx-note" style="left:30px;top:166px">battery {battery_w}%</div>
  <div class="dbx-timing"></div>
  <div style="left:680px;top:108px;line-height:1.3">Timing<br>line</div>
  {tap_html}
  {_status_line(26, 190, box_line[0], box_line[1])}
  {canary_html}
  {_status_line(506, 200, monitor_line[0], monitor_line[1])}
  {"".join(frames)}
</div></div>
"""


def timing_chart(laps: list[tuple[float, float]], deliveries: list[tuple[float, float]],
                 limit_ms: float | None, fault_at_s: float | None, dark: bool) -> alt.LayerChart:
    """Box lap time and monitor delivery time on one millisecond axis, with the alarm limit."""
    ink = _INK[dark]
    rows = [(t, ms, SERIES[0]) for t, ms in laps] + [(t, ms, SERIES[1]) for t, ms in deliveries]
    data = pd.DataFrame(rows, columns=["seconds", "ms", "series"])
    right_edge = max([t for t, _ in laps + deliveries] + [fault_at_s or 0, 1.0])
    top = max([ms for _, ms in laps + deliveries] + [limit_ms or 0, 1.0])
    ceiling = top * 1.3       # an empty band above the highest point: room for both labels, clear of the lines

    base = alt.Chart(data).encode(
        x=alt.X("seconds:Q", title="Seconds since start", scale=alt.Scale(nice=False)),
        y=alt.Y("ms:Q", title="Milliseconds", scale=alt.Scale(domain=[0, ceiling], nice=False)),
        color=alt.Color("series:N", scale=alt.Scale(domain=list(SERIES), range=list(_SERIES_COLORS[dark])),
                        legend=alt.Legend(title=None, orient="top")),
    )
    hover = alt.selection_point(fields=["seconds"], nearest=True, on="pointerover", empty=False, clear="pointerout")
    layers = [
        base.mark_line(strokeWidth=2, strokeCap="round", strokeJoin="round"),
        base.mark_point(filled=True, size=70).encode(
            opacity=alt.condition(hover, alt.value(1), alt.value(0)),
            tooltip=[alt.Tooltip("series:N", title="Series"),
                     alt.Tooltip("seconds:Q", title="Seconds", format=".1f"),
                     alt.Tooltip("ms:Q", title="Milliseconds", format=".2f")],
        ).add_params(hover),
    ]
    if limit_ms:
        limit = pd.DataFrame({"ms": [limit_ms], "seconds": [right_edge], "label": [f"alarm limit {limit_ms:.0f} ms"]})
        layers.append(alt.Chart(limit).mark_rule(color=ink["muted"], strokeWidth=1).encode(y="ms:Q"))
        layers.append(alt.Chart(limit).mark_text(align="right", dy=-7, color=ink["secondary"])
                      .encode(x="seconds:Q", y="ms:Q", text="label:N"))
    if fault_at_s is not None:
        fault = pd.DataFrame({"seconds": [fault_at_s], "ms": [ceiling], "label": ["fault starts"]})
        flip = fault_at_s > 0.75 * right_edge     # near the right edge: put the label on the rule's left
        layers.append(alt.Chart(fault).mark_rule(color=ink["muted"], strokeWidth=1).encode(x="seconds:Q"))
        layers.append(alt.Chart(fault).mark_text(align="right" if flip else "left", dx=-5 if flip else 5, dy=2,
                                                 baseline="top", color=ink["secondary"])
                      .encode(x="seconds:Q", y="ms:Q", text="label:N"))
    return alt.layer(*layers).properties(height=280)


def _escape(text: str) -> str:
    for ch in "\\*_~`[]":
        text = text.replace(ch, "\\" + ch)
    return text


def alarm_lines(alarms: list[tuple[float, str, str]], limit: int = 12) -> list[str]:
    """Newest first. Each line pairs a status badge (colour, icon and label) with the alarm text."""
    lines = []
    for t, source, message in reversed(alarms[-limit:]):
        kind = message.split(":", 1)[0]
        icon = ":material/inventory_2:" if source == "box" else ":material/monitor_heart:"
        badge = "orange-badge" if kind.startswith("slow") else "red-badge"
        lines.append(f":{badge}[{icon} {source}] `{t:5.1f}s` {_escape(message)}")
    return lines
