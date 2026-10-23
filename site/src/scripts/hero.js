// The grade card at the top: it climbs from F to A, the way an app's grade does as its
// problems get fixed, so it's clear F isn't the only grade there is. Each change runs like
// a table being re-read: the letter breaks into cells, the cells flip to the next grade row
// by row in its colour, and the grid settles back into a sharp letter. The scale under the
// card shows any grade on demand. Still for anyone who'd rather not see motion.
const GRADES = [
  ["F", "Orders open to anyone"],
  ["D", "Users read each other's messages"],
  ["C", "Rows added in someone else's name"],
  ["B", "A few things worth a look"],
  ["A", "Every user kept apart"],
];
// The card's own colours (--grade-a to --grade-f in global.css), as hex for the canvas.
const css = getComputedStyle(document.documentElement);
const COLOUR = Object.fromEntries(GRADES.map(([g]) => [g, css.getPropertyValue(`--grade-${g.toLowerCase()}`).trim() || "#5b6372"]));
const DURATION = 900;
// The biggest cell, as a share of the letter's height.
const CELL = 0.085;

const card = document.getElementById("hero-card");
const scale = [...document.querySelectorAll("#hero-scale button")];
const letter = card.querySelector(".p-letter");
const still = matchMedia("(prefers-reduced-motion: reduce)").matches;
let at = 0;
let paused = false;

// The letters as alpha maps, drawn once in the page's own font at the card's size. Until
// they're ready (or if the canvas can't be used), the letter stays plain text.
async function prepare() {
  const size = parseFloat(getComputedStyle(letter).fontSize);
  const ratio = Math.min(devicePixelRatio || 1, 2);
  const w = Math.round(size * 0.82 * ratio);
  const h = Math.round(size * 0.92 * ratio);
  await document.fonts.load(`900 ${size}px "Archivo Variable"`).catch(() => {});
  const font = `normal normal 900 expanded ${size * ratio}px "Archivo Variable", system-ui, sans-serif`;
  const maps = {};
  for (const [grade] of GRADES) {
    const c = Object.assign(document.createElement("canvas"), { width: w, height: h });
    const g = c.getContext("2d", { willReadFrequently: true });
    g.font = font;
    if ("fontStretch" in g) g.fontStretch = "expanded";
    g.textAlign = "center";
    g.textBaseline = "alphabetic";
    const m = g.measureText(grade);
    g.fillStyle = "#000";
    g.fillText(grade, w / 2, h / 2 + (m.actualBoundingBoxAscent - m.actualBoundingBoxDescent) / 2);
    maps[grade] = { image: c, alpha: g.getImageData(0, 0, w, h).data };
  }
  const canvas = Object.assign(document.createElement("canvas"), { width: w, height: h, className: "p-pixels" });
  canvas.style.width = `${w / ratio}px`;
  canvas.style.height = `${h / ratio}px`;
  letter.replaceChildren(canvas);
  return { ctx: canvas.getContext("2d"), maps, w, h, cell: Math.max(4, Math.round(h * CELL)) };
}

// One frame: the old and new letters, the cell size, and how far the scan has got (0 to 1).
function frame(p, from, to, cell, scan) {
  const { ctx, maps, w, h } = p;
  ctx.clearRect(0, 0, w, h);
  if (cell <= 1) {
    // Sharp: the letter itself, in its grade's colour.
    ctx.drawImage(maps[to].image, 0, 0);
    ctx.globalCompositeOperation = "source-in";
    ctx.fillStyle = COLOUR[to];
    ctx.fillRect(0, 0, w, h);
    ctx.globalCompositeOperation = "source-over";
    return;
  }
  const cols = Math.ceil(w / cell);
  const rows = Math.ceil(h / cell);
  const gap = cell > 5 ? Math.max(1, Math.round(cell * 0.14)) : 0;
  for (let y = 0; y < rows; y++) {
    for (let x = 0; x < cols; x++) {
      // Rows flip top to bottom, each cell at a slightly different moment, like bits.
      const noise = (((x * 73856093) ^ (y * 19349663)) >>> 0) % 997 / 997;
      const when = (y / rows) * 0.75 + noise * 0.25;
      const grade = scan > when ? to : from;
      if (coverage(maps[grade].alpha, w, h, x * cell, y * cell, cell) > 0.38) {
        ctx.fillStyle = COLOUR[grade];
        ctx.fillRect(x * cell, y * cell, cell - gap, cell - gap);
      } else if (scan > 0 && scan < 1 && Math.abs(scan - when) < 0.06 && noise > 0.8) {
        // A stray bit lights up as the scan passes.
        ctx.fillStyle = `${COLOUR[to]}40`;
        ctx.fillRect(x * cell, y * cell, cell - gap, cell - gap);
      }
    }
  }
}

// How much of one cell the letter covers, sampled on a coarse grid of its pixels.
function coverage(alpha, w, h, x0, y0, cell) {
  let sum = 0;
  let n = 0;
  const step = Math.max(1, Math.floor(cell / 4));
  for (let y = y0; y < Math.min(y0 + cell, h); y += step) {
    for (let x = x0; x < Math.min(x0 + cell, w); x += step) {
      sum += alpha[(y * w + x) * 4 + 3];
      n++;
    }
  }
  return n ? sum / n / 255 : 0;
}

const drawing = prepare().then((p) => (frame(p, "F", "F", 1, 1), p)).catch(() => null);

function show(i) {
  const from = GRADES[at][0];
  at = i;
  const [grade, sub] = GRADES[i];
  card.className = card.className.replace(/grade-\w+/, `grade-${grade}`);
  card.querySelector(".p-sub").textContent = sub;
  for (const [j, b] of scale.entries()) b.setAttribute("aria-pressed", String(j === i));
  drawing.then((p) => {
    if (!p) return void (letter.textContent = grade);
    if (still || from === grade) return frame(p, grade, grade, 1, 1);
    const start = performance.now();
    const tick = (now) => {
      if (at !== i) return; // a newer change took over
      const t = Math.min(1, (now - start) / DURATION);
      // Break into cells, flip them row by row at the coarsest, then settle back.
      const grow = t < 0.35 ? t / 0.35 : t > 0.65 ? (1 - t) / 0.35 : 1;
      const cell = Math.max(1, Math.round(1 + (p.cell - 1) * ease(grow)));
      const scan = t < 0.3 ? 0 : t > 0.72 ? 1 : (t - 0.3) / 0.42;
      frame(p, from, grade, t >= 1 ? 1 : cell, scan);
      if (t < 1) requestAnimationFrame(tick);
    };
    requestAnimationFrame(tick);
  });
}

function ease(x) {
  return x < 0.5 ? 2 * x * x : 1 - (-2 * x + 2) ** 2 / 2;
}

for (const [i, b] of scale.entries()) b.addEventListener("click", () => show(i));
for (const el of [card, ...scale]) {
  el.addEventListener("pointerenter", () => (paused = true));
  el.addEventListener("pointerleave", () => (paused = false));
}
if (!still) setInterval(() => !paused && !document.hidden && show((at + 1) % GRADES.length), 3000);
