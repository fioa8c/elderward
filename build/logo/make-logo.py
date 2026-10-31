"""Regenerates the Elderward logo files from the geometry of the website's ward
and the IM Fell English typeface, so no font ships with the plugin.

    pip install fonttools uharfbuzz
    # drop IM FELL English Roman as fonts/imfell.ttf and Anonymous Pro 400/700 as
    # fonts/anonymous-400.woff / fonts/anonymous-700.woff (both are OFL, from Google Fonts)
    python3 build/logo/make-logo.py && node build/logo/render.js

Writes assets/img/*.svg, .wordpress-org/icon.svg and the HTML sources for the PNGs."""
import math, os, sys
import uharfbuzz as hb
from fontTools.ttLib import TTFont
from fontTools.pens.svgPathPen import SVGPathPen
from fontTools.pens.transformPen import TransformPen
from fontTools.pens.boundsPen import BoundsPen

SP = os.path.dirname(os.path.abspath(__file__))          # build/logo
REPO = os.path.dirname(os.path.dirname(SP))
OUT = os.path.join(SP, "out")
FONT = os.path.join(SP, "fonts", "imfell.ttf")   # IM FELL English Roman

# palette from site/index.html
ABYSS, BRINE, KELP = "#061614", "#0e2b27", "#173d37"
VERDIGRIS, VERDIGRIS_DIM = "#7dbfaa", "#4f8676"
BONE, BONE_DIM = "#dcd3b0", "#a59e86"
SIGIL = "#d9ae55"
SIGIL_DEEP = "#a67d2a"   # the same gold, darkened for white backgrounds

def fmt(v):
    s = ("%.2f" % v).rstrip("0").rstrip(".")
    return "0" if s in ("-0", "") else s

#### the mark: pentagram, warding ring, eye and flame (geometry from the site's canvas ward)
def mark_markup(star=SIGIL, ring=BONE, scale=1.0, dx=0.0, dy=0.0):
    cx, cy, R = 50.0, 50.0, 34.0
    def P(x, y):
        return (dx + (x - 50) * scale + 50, dy + (y - 50) * scale + 50)
    rp = R * 1.08
    pts = []
    for k in range(5):
        a = -math.pi / 2 + k * 2 * math.pi / 5
        pts.append(P(cx + rp * math.cos(a), cy + rp * math.sin(a)))
    order = [0, 2, 4, 1, 3]
    star_d = "M" + " L".join("%s %s" % (fmt(pts[i][0]), fmt(pts[i][1])) for i in order) + " Z"
    ey = cy + R * 0.03
    ew, eh = R * 0.30, R * 0.15
    l, r = P(cx - ew, ey), P(cx + ew, ey)
    top, bot = P(cx, ey - 2 * eh), P(cx, ey + 2 * eh)
    eye_d = "M%s %s Q%s %s %s %s Q%s %s %s %s Z" % tuple(fmt(v) for v in (l + top + r + bot + l))
    f0 = P(cx, ey - eh * 1.15)
    f1 = P(cx - ew * 0.35, ey - R * 0.30)
    f2 = P(cx + ew * 0.30, ey - R * 0.38)
    f3 = P(cx, ey - R * 0.55)
    flame_d = "M%s %s C%s %s %s %s %s %s" % tuple(fmt(v) for v in (f0 + f1 + f2 + f3))
    ccx, ccy = P(cx, cy)
    pcx, pcy = P(cx, ey)
    s = scale
    return "\n".join([
        '  <circle cx="%s" cy="%s" r="%s" fill="none" stroke="%s" stroke-width="%s"/>' % (fmt(ccx), fmt(ccy), fmt(R * 1.1 * s), ring, fmt(1.4 * s)),
        '  <path d="%s" fill="none" stroke="%s" stroke-width="%s" stroke-linejoin="round"/>' % (star_d, star, fmt(2.4 * s)),
        '  <path d="%s" fill="none" stroke="%s" stroke-width="%s" stroke-linejoin="round"/>' % (eye_d, star, fmt(2.4 * s)),
        '  <circle cx="%s" cy="%s" r="%s" fill="%s"/>' % (fmt(pcx), fmt(pcy), fmt(eh * 0.85 * s), star),
        '  <path d="%s" fill="none" stroke="%s" stroke-width="%s" stroke-linecap="round"/>' % (flame_d, star, fmt(2.0 * s)),
    ])

#### the wordmark: "Elderward" shaped with HarfBuzz (kerning) and outlined with fontTools
def wordmark(text="Elderward", cap_height=46.0):
    tt = TTFont(FONT)
    upem = tt["head"].unitsPerEm
    cap = tt["OS/2"].sCapHeight
    s = cap_height / cap
    blob = hb.Blob.from_file_path(FONT)
    face = hb.Face(blob)
    font = hb.Font(face)
    buf = hb.Buffer()
    buf.add_str(text)
    buf.guess_segment_properties()
    hb.shape(font, buf, {"kern": True, "liga": True})
    glyph_order = tt.getGlyphOrder()
    gs = tt.getGlyphSet()
    pen = SVGPathPen(gs, ntos=fmt)
    x = 0.0
    for info, pos in zip(buf.glyph_infos, buf.glyph_positions):
        name = glyph_order[info.codepoint]
        # font units -> output units, flip y so the baseline is y=0 and glyphs rise upwards
        t = (s, 0, 0, -s, (x + pos.x_offset) * s, -pos.y_offset * s)
        gs[name].draw(TransformPen(pen, t))
        x += pos.x_advance
    d = pen.getCommands()
    bp = BoundsPen(gs)
    # bounds in output units
    x2 = 0.0
    xmin = ymin = 1e9; xmax = ymax = -1e9
    for info, pos in zip(buf.glyph_infos, buf.glyph_positions):
        name = glyph_order[info.codepoint]
        b = BoundsPen(gs); gs[name].draw(b)
        if b.bounds:
            bx0, by0, bx1, by1 = b.bounds
            xmin = min(xmin, (x2 + bx0) * s); xmax = max(xmax, (x2 + bx1) * s)
            ymin = min(ymin, -by1 * s); ymax = max(ymax, -by0 * s)
        x2 += pos.x_advance
    return d, (xmin, ymin, xmax, ymax), x2 * s

def svg(w, h, body, extra_attrs=""):
    return ('<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 %s %s" width="%s" height="%s"%s>\n%s\n</svg>\n'
            % (fmt(w), fmt(h), fmt(w), fmt(h), extra_attrs, body))

def write(path, content):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, "w") as fh:
        fh.write(content)
    print("wrote", path, len(content), "bytes")

title = "<title>Elderward</title>\n"
# 1. the bare mark, transparent background (for dark surfaces)
write(os.path.join(REPO, "assets/img/elderward-mark.svg"),
      svg(100, 100, title + mark_markup()))

# 2. the mark for light surfaces
write(os.path.join(REPO, "assets/img/elderward-mark-on-light.svg"),
      svg(100, 100, title + mark_markup(star=SIGIL_DEEP, ring=KELP)))

# 3. the lockup: mark + wordmark
d, (x0, y0, x1, y1), adv = wordmark()
gap = 14.0
text_x = 100 + gap - x0
cap_top = 50 - 46 / 2.0
baseline = cap_top + 46
width = text_x + x1 + 2
def lockup(star, ring, ink):
    body = title + mark_markup(star=star, ring=ring)
    body += '\n  <path transform="translate(%s %s)" d="%s" fill="%s"/>' % (fmt(text_x), fmt(baseline), d, ink)
    return svg(width, 100, body, ' role="img" aria-label="Elderward"')
write(os.path.join(REPO, "assets/img/elderward-logo.svg"), lockup(SIGIL, BONE, BONE))
write(os.path.join(REPO, "assets/img/elderward-logo-on-light.svg"), lockup(SIGIL_DEEP, KELP, "#1d2327"))

# 4. wordmark alone (dark surfaces), tight viewBox
wm_w = x1 - x0 + 2
wm_body = title + '  <path transform="translate(%s %s)" d="%s" fill="%s"/>' % (fmt(1 - x0), fmt(-y0 + 1), d, BONE)
write(os.path.join(REPO, "assets/img/elderward-wordmark.svg"), svg(wm_w, y1 - y0 + 2, wm_body, ' role="img" aria-label="Elderward"'))

# 5. wordpress.org icon: abyss square with the mark
icon_body = title + '  <rect width="100" height="100" fill="%s"/>\n' % ABYSS + mark_markup(scale=0.92)
write(os.path.join(REPO, ".wordpress-org/icon.svg"), svg(100, 100, icon_body))

# 6. HTML pages for the PNG renders (banner + icons), rendered by Playwright
def page(w, h, inner, css):
    return """<!doctype html><html><head><meta charset="utf-8"><style>
@font-face{font-family:"Anonymous Pro";src:url("../fonts/anonymous-400.woff") format("woff");font-weight:400}
@font-face{font-family:"Anonymous Pro";src:url("../fonts/anonymous-700.woff") format("woff");font-weight:700}
html,body{margin:0;background:%s}
body{width:%dpx;height:%dpx;overflow:hidden;position:relative;font-family:"Anonymous Pro",monospace;-webkit-font-smoothing:antialiased}
%s
</style></head><body>%s</body></html>""" % (ABYSS, w, h, css, inner)

mark_svg_dark = svg(100, 100, mark_markup())
for W, H, k in ((1544, 500, 2), (772, 250, 1)):
    css = """
.bg{position:absolute;inset:0;background:
 radial-gradient(ellipse 60%% 90%% at 78%% 50%%, rgba(23,61,55,.75), transparent 70%%),
 radial-gradient(ellipse 90%% 70%% at 8%% 100%%, rgba(14,43,39,.8), transparent 70%%), %s}
.scan{position:absolute;inset:0;background:repeating-linear-gradient(to bottom, rgba(0,0,0,.11) 0 %dpx, transparent %dpx %dpx);mix-blend-mode:multiply}
.mark{position:absolute;right:%dpx;top:%dpx;width:%dpx;height:%dpx;filter:drop-shadow(0 0 %dpx rgba(217,174,85,.28))}
.text{position:absolute;left:%dpx;top:%dpx}
.mark svg{display:block;width:100%%;height:100%%}
.text svg{display:block;width:%dpx;height:auto}
.tag{margin:%dpx 0 0 %dpx;color:%s;font-size:%dpx;line-height:1.45;white-space:nowrap}
.tag b{color:%s;font-weight:400}
""" % (ABYSS, k, k, 3 * k, 70 * k, 35 * k, 180 * k, 180 * k, 18 * k, 64 * k, 72 * k, 300 * k, 20 * k, 2 * k, BONE_DIM, 15 * k, VERDIGRIS)
    wm = svg(wm_w, y1 - y0 + 2, '  <path transform="translate(%s %s)" d="%s" fill="%s"/>' % (fmt(1 - x0), fmt(-y0 + 1), d, BONE))
    inner = ('<div class="bg"></div><div class="mark">%s</div><div class="text">%s<p class="tag">Malware scanner and incident response for WordPress.<br><b>Finds what crept in, and shows you how it got in.</b></p></div><div class="scan"></div>'
             % (mark_svg_dark, wm))
    write(os.path.join(OUT, "banner-%dx%d.html" % (W, H)), page(W, H, inner, css))

for S in (128, 256):
    inner = '<div style="position:absolute;inset:0;background:radial-gradient(circle at 50%% 45%%, rgba(23,61,55,.7), transparent 72%%), %s"></div><div style="position:absolute;inset:0">%s</div>' % (ABYSS, svg(100, 100, mark_markup(scale=0.92)).replace('width="100" height="100"', 'width="%d" height="%d"' % (S, S)))
    write(os.path.join(OUT, "icon-%dx%d.html" % (S, S)), page(S, S, inner, ""))
print("wordmark bounds", x0, y0, x1, y1, "lockup width", width)
