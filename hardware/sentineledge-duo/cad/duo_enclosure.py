"""SentinelEdge Duo enclosure: one box for a Raspberry Pi 5 (sensor) and a Jetson Orin Nano (brain).

Parametric CSG model (manifold3d). Running it writes, next to this file's parent:

    stl/duo_base.stl          the tray: floor, walls, standoffs, panel cut-outs, vents
    stl/duo_lid.stl           the lid: vent slots, screw holes, locating lip
    stl/duo_assembly.stl      everything, boards included, for a visual check (not for printing)
    renders/*.png             preview images used in BUILD_GUIDE.md
    viewer.html               interactive 3D view (open in a browser; three.js from a CDN)

    python3 duo_enclosure.py            # needs: pip install manifold3d numpy matplotlib

All sizes are millimetres. Board sizes come from the vendors' published
mechanical data; CHECK THE MOUNTING HOLES OF YOUR OWN BOARDS WITH CALIPERS
before printing (see BUILD_GUIDE.md, step 1) and change the constants below.
"""
import base64
import json
import os
import struct

import numpy as np
from manifold3d import Manifold

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.dirname(HERE)

# ---------------- parameters ----------------
WALL = 3.0                      # wall and floor thickness
OUTER = (240.0, 170.0, 76.0)    # outer width (x), depth (y), height (z) with the lid on
LID = 3.0                       # lid plate thickness
CORNER_R = 6.0                  # rounded vertical corners
STANDOFF_H = 6.0                # board standoff height above the floor
M25_INSERT = 3.6                # hole for an M2.5 heat-set insert
M3_INSERT = 4.2                 # hole for an M3 heat-set insert (lid screws)
M3_CLEAR = 3.4

# boards: origin = board corner nearest the box's front-left, placed on the floor (inner coords)
PI5 = dict(size=(85.0, 56.0, 1.6), height=20.0,                      # with the official active cooler
           holes=[(3.5, 3.5), (61.5, 3.5), (3.5, 52.5), (61.5, 52.5)], at=(140.0, 98.0))
JETSON = dict(size=(103.0, 90.5, 1.6), height=34.8,                  # Orin Nano Developer Kit incl. heatsink
              # carrier hole pattern 86 x 58 mm (Jetson Nano-family layout): VERIFY on your carrier
              holes=[(8.5, 16.0), (94.5, 16.0), (8.5, 74.0), (94.5, 74.0)], at=(10.0, 64.0))
SWITCH = dict(size=(70.0, 50.0, 1.6), height=18.0,                   # 5-port gigabit switch board
              holes=[(3.5, 3.5), (66.5, 3.5), (3.5, 46.5), (66.5, 46.5)], at=(150.0, 38.0))  # behind the keystone jacks (~30 mm deep)
BUCK = dict(size=(60.0, 32.0, 1.6), height=15.0,                     # 19 V -> 5 V 5 A DC-DC module
            holes=[(3.0, 3.0), (57.0, 3.0), (3.0, 29.0), (57.0, 29.0)], at=(14.0, 16.0))

# front panel (y = 0): three keystone RJ45 couplers, three LEDs, a power button
KEYSTONE = (14.9, 19.3)         # standard keystone jack cut-out
KEYSTONE_X = (162.0, 186.0, 210.0)
KEYSTONE_Z = 34.0
LED_X = (40.0, 52.0, 64.0)
LED_D = 5.2                     # 5 mm LED holder
BUTTON_X, BUTTON_D = 90.0, 12.2  # 12 mm momentary button
PANEL_Z = 30.0
# left wall (x = 0): DC inlet, rocker switch, intake vents
DC_JACK_D = 11.2                # panel-mount 5.5 x 2.5 mm jack
ROCKER = (19.2, 13.0)
# right wall (x = W): 60 mm exhaust fan
FAN = 60.0
FAN_SCREW = 50.0
FAN_CENTER = (115.0, 40.0)      # (y, z)
# rear wall: service window for the Jetson's I/O (USB, DisplayPort) and a Pi window (USB-C, micro-HDMI)
JETSON_WINDOW = (18.0, 100.0, 12.0, 34.0)   # x0, x1, z0, z1
LID_SCREWS_INSET = 7.0

W, D, H = OUTER
BASE_H = H - LID


def box(x, y, z, at=(0, 0, 0)):
    return Manifold.cube([x, y, z]).translate(list(at))


def cyl(h, r, at=(0, 0, 0), seg=48):
    return Manifold.cylinder(h, r, r, seg).translate(list(at))


def rounded_box(x, y, z, r, at=(0, 0, 0)):
    core = box(x - 2 * r, y, z, (r, 0, 0)) + box(x, y - 2 * r, z, (0, r, 0))
    for cx in (r, x - r):
        for cy in (r, y - r):
            core = core + cyl(z, r, (cx, cy, 0))
    return core.translate(list(at))


def slots(n, length, width, pitch, axis, at, depth):
    """n parallel slots through a wall. axis: 'x' wall (cut along x) or 'y' wall."""
    out = Manifold()
    for i in range(n):
        if axis == 'y':       # slot in a wall normal to x, slots spread along y, vertical
            out = out + box(depth, width, length, (at[0], at[1] + i * pitch, at[2]))
        elif axis == 'x':     # wall normal to y
            out = out + box(width, depth, length, (at[0] + i * pitch, at[1], at[2]))
        else:                 # lid: slots spread along x, long in y
            out = out + box(width, length, depth, (at[0] + i * pitch, at[1], at[2]))
    return out


def standoffs(board):
    bx, by = board['at']
    out = Manifold()
    holes = Manifold()
    for hx, hy in board['holes']:
        x, y = WALL + bx + hx, WALL + by + hy
        out = out + cyl(STANDOFF_H + WALL, 3.2, (x, y, 0))
        holes = holes + cyl(STANDOFF_H + 1, M25_INSERT / 2, (x, y, WALL))
    return out, holes


def lid_screw_points():
    i = LID_SCREWS_INSET
    return [(i, i), (W - i, i), (i, D - i), (W - i, D - i)]


def base():
    shell = rounded_box(W, D, BASE_H, CORNER_R) - rounded_box(W - 2 * WALL, D - 2 * WALL, BASE_H, CORNER_R - WALL,
                                                             (WALL, WALL, WALL))
    cuts = Manifold()
    for board in (PI5, JETSON, SWITCH, BUCK):
        s, h = standoffs(board)
        shell = shell + s
        cuts = cuts + h
    # lid screw bosses in the corners
    for x, y in lid_screw_points():
        shell = shell + cyl(BASE_H, 5.0, (x, y, 0))
        cuts = cuts + cyl(14, M3_INSERT / 2, (x, y, BASE_H - 12))
    # front panel
    for x in KEYSTONE_X:
        cuts = cuts + box(KEYSTONE[0], WALL + 2, KEYSTONE[1], (x - KEYSTONE[0] / 2, -1, KEYSTONE_Z - KEYSTONE[1] / 2))
    for x in LED_X:
        cuts = cuts + Manifold.cylinder(WALL + 2, LED_D / 2, LED_D / 2, 32).rotate([-90, 0, 0]).translate(
            [x, -1, PANEL_Z])
    cuts = cuts + Manifold.cylinder(WALL + 2, BUTTON_D / 2, BUTTON_D / 2, 48).rotate([-90, 0, 0]).translate(
        [BUTTON_X, -1, PANEL_Z])
    # left wall: DC jack, rocker, intake slots behind them
    cuts = cuts + Manifold.cylinder(WALL + 2, DC_JACK_D / 2, DC_JACK_D / 2, 48).rotate([0, 90, 0]).translate(
        [-1, 30, 30])
    cuts = cuts + box(WALL + 2, ROCKER[0], ROCKER[1], (-1, 45, 30 - ROCKER[1] / 2))
    cuts = cuts + slots(14, 40, 3.0, 6.0, 'y', (-1, 75, 14), WALL + 2)
    # right wall: fan grille (rings of holes) and screw holes
    fy, fz = FAN_CENTER
    grille = Manifold()
    for rr, n in ((0, 1), (8, 8), (16, 14), (24, 20)):
        for k in range(n):
            a = 2 * np.pi * k / n
            grille = grille + Manifold.cylinder(WALL + 2, 2.6, 2.6, 16).rotate([0, 90, 0]).translate(
                [W - WALL - 1, fy + rr * np.cos(a), fz + rr * np.sin(a)])
    for dy in (-FAN_SCREW / 2, FAN_SCREW / 2):
        for dz in (-FAN_SCREW / 2, FAN_SCREW / 2):
            grille = grille + Manifold.cylinder(WALL + 2, 1.7, 1.7, 16).rotate([0, 90, 0]).translate(
                [W - WALL - 1, fy + dy, fz + dz])
    cuts = cuts + grille
    # rear wall: Jetson service window, Pi USB-C / micro-HDMI window (maintenance only)
    x0, x1, z0, z1 = JETSON_WINDOW
    cuts = cuts + box(x1 - x0, WALL + 2, z1 - z0, (x0, D - WALL - 1, z0))
    cuts = cuts + box(40, WALL + 2, 12, (WALL + PI5['at'][0] + 10, D - WALL - 1, WALL + STANDOFF_H + 1))
    # floor: recesses for 4 rubber feet (10 mm) and a row of floor vents under the Jetson
    for x, y in ((20, 20), (W - 20, 20), (20, D - 20), (W - 20, D - 20)):
        cuts = cuts + cyl(1.0, 5.5, (x, y, -0.01))
    cuts = cuts + slots(10, 50, 3.0, 8.0, 'z', (WALL + JETSON['at'][0] + 12, WALL + JETSON['at'][1] + 2, -1), WALL + 2)
    return shell - cuts


def lid():
    plate = rounded_box(W, D, LID, CORNER_R)
    lip = rounded_box(W - 2 * WALL - 0.6, D - 2 * WALL - 0.6, 3, CORNER_R - WALL, (WALL + 0.3, WALL + 0.3, -3)) - \
        rounded_box(W - 2 * WALL - 4.6, D - 2 * WALL - 4.6, 3, CORNER_R - WALL - 2, (WALL + 2.3, WALL + 2.3, -3))
    part = plate + lip
    cuts = Manifold()
    for x, y in lid_screw_points():
        cuts = cuts + cyl(LID + 4, M3_CLEAR / 2, (x, y, -3.5)) + cyl(1.6, 3.2, (x, y, LID - 1.6))
        part = part - cyl(3, 6.0, (x, y, -3))          # clear the corner bosses
    # vent slots over the Jetson heatsink and over the Pi cooler
    jx, jy = WALL + JETSON['at'][0], WALL + JETSON['at'][1]
    cuts = cuts + slots(12, 70, 3.0, 7.0, 'z', (jx + 12, jy + 10, -4), LID + 5)
    px, py = WALL + PI5['at'][0], WALL + PI5['at'][1]
    cuts = cuts + slots(8, 40, 3.0, 7.0, 'z', (px + 15, py + 8, -4), LID + 5)
    return (part - cuts).translate([0, 0, BASE_H])


def board_block(board, top_extra=0.0):
    bx, by = board['at']
    x, y, _ = board['size']
    z0 = WALL + STANDOFF_H
    return box(x, y, board['height'], (WALL + bx, WALL + by, z0))


def mesh_arrays(m):
    mesh = m.to_mesh()
    return np.asarray(mesh.vert_properties)[:, :3].astype(np.float32), np.asarray(mesh.tri_verts).astype(np.uint32)


def write_stl(path, m):
    v, t = mesh_arrays(m)
    tri = v[t]
    n = np.cross(tri[:, 1] - tri[:, 0], tri[:, 2] - tri[:, 0])
    n /= np.maximum(np.linalg.norm(n, axis=1, keepdims=True), 1e-9)
    with open(path, 'wb') as f:
        f.write(b'SentinelEdge Duo'.ljust(80, b' '))
        f.write(struct.pack('<I', len(t)))
        rec = np.zeros(len(t), dtype=[('n', '<f4', 3), ('v', '<f4', (3, 3)), ('a', '<u2')])
        rec['n'], rec['v'] = n, tri
        f.write(rec.tobytes())


PARTS_COLORS = {'base': '#9aa5b1', 'lid': '#c9d1d9', 'pi5': '#2e9e5b', 'jetson': '#76b900',
                'switch': '#3b6fd6', 'buck': '#d67b3b'}


def render_png(parts, path, elev, azim, title, hide=()):
    import matplotlib
    matplotlib.use('Agg')
    import matplotlib.pyplot as plt
    from mpl_toolkits.mplot3d.art3d import Poly3DCollection
    fig = plt.figure(figsize=(9, 6), dpi=120)
    ax = fig.add_subplot(111, projection='3d')
    light = np.array([0.4, -0.6, 0.7]) / np.linalg.norm([0.4, -0.6, 0.7])
    for name, m in parts.items():
        if name in hide:
            continue
        v, t = mesh_arrays(m)
        tri = v[t]
        n = np.cross(tri[:, 1] - tri[:, 0], tri[:, 2] - tri[:, 0])
        n /= np.maximum(np.linalg.norm(n, axis=1, keepdims=True), 1e-9)
        shade = 0.45 + 0.55 * np.clip(n @ light, 0, 1)
        base_rgb = np.array(matplotlib.colors.to_rgb(PARTS_COLORS[name]))
        colors = np.clip(base_rgb[None, :] * shade[:, None], 0, 1)
        alpha = 0.35 if name == 'base' and 'lid' in hide else 1.0
        ax.add_collection3d(Poly3DCollection(tri, facecolors=np.c_[colors, np.full(len(colors), alpha)],
                                             linewidths=0))
    ax.set_xlim(0, W)
    ax.set_ylim(0, D)
    ax.set_zlim(0, H)
    ax.set_box_aspect((W, D, H))
    ax.view_init(elev=elev, azim=azim)
    ax.set_axis_off()
    ax.set_title(title)
    fig.tight_layout()
    fig.savefig(path)
    plt.close(fig)


VIEWER = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>SentinelEdge Duo</title>
<style>
:root{--bg:#f5f6f8;--fg:#1d232b;--panel:#ffffffd9}
@media (prefers-color-scheme:dark){:root{--bg:#14181d;--fg:#e6e9ed;--panel:#1d232bd9}}
html,body{margin:0;height:100%;background:var(--bg);color:var(--fg);font:14px system-ui,sans-serif}
#ui{position:absolute;top:12px;left:12px;background:var(--panel);padding:10px 14px;border-radius:8px;max-width:calc(100% - 56px)}
#ui label{display:inline-block;margin:4px 10px 4px 0;white-space:nowrap}
canvas{display:block}
</style></head><body>
<div id="ui"><strong>SentinelEdge Duo</strong> (drag to rotate, scroll to zoom)<br><span id="toggles"></span></div>
<script src="https://cdnjs.cloudflare.com/ajax/libs/three.js/r128/three.min.js"></script>
<script src="https://cdn.jsdelivr.net/npm/three@0.128.0/examples/js/controls/OrbitControls.js"></script>
<script>
const PARTS = __PARTS__;
const scene = new THREE.Scene();
const camera = new THREE.PerspectiveCamera(40, innerWidth / innerHeight, 1, 5000);
camera.position.set(260, -300, 260); camera.up.set(0, 0, 1);
const renderer = new THREE.WebGLRenderer({antialias: true, alpha: true});
renderer.setPixelRatio(devicePixelRatio); renderer.setSize(innerWidth, innerHeight);
document.body.appendChild(renderer.domElement);
const controls = new THREE.OrbitControls(camera, renderer.domElement);
controls.target.set(__CX__, __CY__, __CZ__); controls.update();
scene.add(new THREE.AmbientLight(0xffffff, 0.55));
const sun = new THREE.DirectionalLight(0xffffff, 0.75); sun.position.set(200, -300, 400); scene.add(sun);
const toggles = document.getElementById('toggles');
for (const p of PARTS) {
  const v = new Float32Array(Uint8Array.from(atob(p.v), c => c.charCodeAt(0)).buffer);
  const t = new Uint32Array(Uint8Array.from(atob(p.t), c => c.charCodeAt(0)).buffer);
  const g = new THREE.BufferGeometry();
  g.setAttribute('position', new THREE.BufferAttribute(v, 3)); g.setIndex(new THREE.BufferAttribute(t, 1));
  g.computeVertexNormals();
  const mat = new THREE.MeshStandardMaterial({color: p.color, metalness: 0.1, roughness: 0.7,
                                              transparent: p.name === 'lid', opacity: p.name === 'lid' ? 0.45 : 1});
  const mesh = new THREE.Mesh(g, mat); scene.add(mesh);
  const id = 'cb-' + p.name, lab = document.createElement('label');
  lab.innerHTML = `<input type="checkbox" id="${id}" checked> ${p.label}`; toggles.appendChild(lab);
  lab.querySelector('input').onchange = e => { mesh.visible = e.target.checked; };
}
addEventListener('resize', () => { camera.aspect = innerWidth / innerHeight; camera.updateProjectionMatrix();
                                   renderer.setSize(innerWidth, innerHeight); });
(function loop() { requestAnimationFrame(loop); renderer.render(scene, camera); })();
</script></body></html>
"""

LABELS = {'base': 'Base tray', 'lid': 'Lid', 'pi5': 'Raspberry Pi 5 (sensor)', 'jetson': 'Jetson Orin Nano (brain)',
          'switch': 'Internal switch', 'buck': '19 V to 5 V converter'}


def main():
    os.makedirs(os.path.join(OUT, 'stl'), exist_ok=True)
    os.makedirs(os.path.join(OUT, 'renders'), exist_ok=True)
    b, l = base(), lid()
    parts = {'base': b, 'lid': l, 'pi5': board_block(PI5), 'jetson': board_block(JETSON),
             'switch': board_block(SWITCH), 'buck': board_block(BUCK)}
    write_stl(os.path.join(OUT, 'stl', 'duo_base.stl'), b)
    # print the lid upside down: flat face on the bed
    write_stl(os.path.join(OUT, 'stl', 'duo_lid.stl'), l.translate([0, 0, -BASE_H]).mirror([0, 0, 1]).translate([0, 0, LID]))
    assembly = Manifold()
    for m in parts.values():
        assembly = assembly + m
    write_stl(os.path.join(OUT, 'stl', 'duo_assembly.stl'), assembly)
    r = os.path.join(OUT, 'renders')
    render_png(parts, os.path.join(r, 'assembly.png'), 28, -60, 'SentinelEdge Duo, closed')
    render_png(parts, os.path.join(r, 'inside.png'), 55, -70, 'Lid removed: Jetson (left), Pi 5 (rear right), '
               'switch (front right), converter (front left)', hide=('lid',))
    render_png(parts, os.path.join(r, 'front.png'), 8, -90, 'Front: LEDs, power button, NET IN / NET OUT / MGMT')
    render_png(parts, os.path.join(r, 'rear_left.png'), 15, 130, 'Rear and left: service window, DC inlet, '
               'switch, intake vents')
    payload = []
    for name, m in parts.items():
        v, t = mesh_arrays(m)
        payload.append({'name': name, 'label': LABELS[name], 'color': PARTS_COLORS[name],
                        'v': base64.b64encode(v.tobytes()).decode(), 't': base64.b64encode(t.tobytes()).decode()})
    html = VIEWER.replace('__PARTS__', json.dumps(payload)).replace('__CX__', str(W / 2)) \
        .replace('__CY__', str(D / 2)).replace('__CZ__', str(H / 2))
    with open(os.path.join(OUT, 'viewer.html'), 'w', encoding='utf-8') as f:
        f.write(html)
    for name in ('duo_base', 'duo_lid'):
        m = b if name == 'duo_base' else l
        v, t = mesh_arrays(m)
        lo, hi = v.min(0), v.max(0)
        print(f'{name}.stl: {len(t)} triangles, {hi[0] - lo[0]:.1f} x {hi[1] - lo[1]:.1f} x {hi[2] - lo[2]:.1f} mm, '
              f'volume {m.volume() / 1000:.0f} cm3')


if __name__ == '__main__':
    main()
