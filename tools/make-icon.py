#!/usr/bin/env python3
"""Builds the app icon (HVIF) from the Proton VPN sign of the GTK app
(assets/icons/proton-vpn-sign.svg): the four gradient-filled paths, scaled
from the SVG's 25-unit view box to Haiku's 64 x 64 icon canvas.

    python3 tools/make-icon.py resources/proton-vpn.hvif [preview.png]
"""
import os
import re
import sys

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import hvif  # noqa: E402

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SVG = os.path.join(ROOT, '.upstream/proton-vpn-gtk-app/proton/vpn/app/gtk/assets/icons/proton-vpn-sign.svg')
VIEW_X, VIEW_Y, VIEW_SIZE = 12.0, 13.0, 25.0
SCALE, OFFSET = 62.0 / VIEW_SIZE, 1.0
GRADIENT_SHIFT_Y = -792.0   # the SVG's gradientTransform


def canvas(x, y):
    return ((x - VIEW_X) * SCALE + OFFSET, (y - VIEW_Y) * SCALE + OFFSET)


def parse_path(d):
    """SVG path data (M, L, l, c, C, z) to HVIF points with handles."""
    tokens = re.findall(r'[MmLlCcZz]|-?\d*\.?\d+(?:e-?\d+)?', d)
    nodes = []
    i = 0
    command = None
    current = (0.0, 0.0)

    def number():
        nonlocal i
        value = float(tokens[i])
        i += 1
        return value

    while i < len(tokens):
        token = tokens[i]
        if re.match(r'[MmLlCcZz]', token):
            command = token
            i += 1
            if command in 'Zz':
                if len(nodes) > 1 and abs(nodes[-1]['p'][0] - nodes[0]['p'][0]) < 1e-6 \
                        and abs(nodes[-1]['p'][1] - nodes[0]['p'][1]) < 1e-6:
                    nodes[0]['in'] = nodes[-1]['in']
                    nodes.pop()
                continue
        if command in 'Mm':
            x, y = number(), number()
            if command == 'm':
                x, y = current[0] + x, current[1] + y
            current = (x, y)
            nodes.append({'p': current, 'in': current, 'out': current})
            command = 'l' if command == 'm' else 'L'
        elif command in 'Ll':
            x, y = number(), number()
            if command == 'l':
                x, y = current[0] + x, current[1] + y
            if (x, y) == current:
                continue
            current = (x, y)
            nodes.append({'p': current, 'in': current, 'out': current})
        elif command in 'Cc':
            values = [number() for _ in range(6)]
            if command == 'c':
                values = [current[0] + values[0], current[1] + values[1],
                          current[0] + values[2], current[1] + values[3],
                          current[0] + values[4], current[1] + values[5]]
            nodes[-1]['out'] = (values[0], values[1])
            current = (values[4], values[5])
            nodes.append({'p': current, 'in': (values[2], values[3]), 'out': current})
    return [(canvas(*n['p']), canvas(*n['in']), canvas(*n['out'])) for n in nodes]


def main():
    svg = open(SVG).read()
    gradients = {}
    for match in re.finditer(r'<linearGradient id="([^"]+)"[^>]*x1="([^"]+)" y1="([^"]+)" '
                             r'x2="([^"]+)" y2="([^"]+)"[^>]*>(.*?)</linearGradient>', svg, re.S):
        gid, x1, y1, x2, y2, body = match.groups()
        stops = [(float(offset), hvif.hex_color(color)) for offset, color in
                 re.findall(r'offset="([^"]+)" style="stop-color:#([0-9A-Fa-f]{6})"', body)]
        start = canvas(float(x1), float(y1) + GRADIENT_SHIFT_Y)
        end = canvas(float(x2), float(y2) + GRADIENT_SHIFT_Y)
        gradients[gid] = hvif.linear_gradient(start, end, stops)
    classes = dict(re.findall(r'\.(st\d)\{[^}]*fill:url\(#([^)]+)\)', svg))
    icon = {'styles': [], 'paths': [], 'shapes': []}
    for match in re.finditer(r'<path (?:class="(st\d)"|style="[^"]*fill:url\(#([^)]+)\);") d="([^"]+)"', svg, re.S):
        css, gid, d = match.groups()
        gid = gid or classes[css]
        icon['styles'].append(gradients[gid])
        icon['paths'].append({'closed': True, 'points': parse_path(d)})
        icon['shapes'].append({'style': len(icon['styles']) - 1, 'paths': [len(icon['paths']) - 1]})
    out = sys.argv[1] if len(sys.argv) > 1 else 'proton-vpn.hvif'
    data = hvif.encode(icon)
    hvif.decode(data)
    with open(out, 'wb') as f:
        f.write(data)
    print('%s: %d bytes, %d shapes' % (out, len(data), len(icon['shapes'])))
    if len(sys.argv) > 2:
        image = hvif.preview(icon, 256)
        image.save(sys.argv[2])


main()
