// "Share your grade": a 1200×630 picture of the inspection for X, LinkedIn and the like,
// drawn in the page's paperwork. It shows the grade and how many problems of each kind,
// never what they are: a live app's holes aren't something to post. The app's name is
// shown only for a public GitHub repository, and only if its owner leaves it on.
const W = 1200;
const H = 630;
const SITE = "https://zkousama.github.io/rls-probe/";
const INK = "#1d3b8c";
const TEXT = "#1b1f27";
const MUTED = "#5b6372";
const PAPER = "#fbfbf8";
const CARD = "#fffdf6";
const GRADE = { A: "#1d3b8c", B: "#1f7a4d", C: "#b45a00", D: "#c2410c", F: "#c2142d" };
const SEVERITY = [["critical", "critical", "#c2142d"], ["high", "high", "#c2410c"], ["medium", "medium", "#b45a00"]];
const FONT = "'Archivo Variable', system-ui, sans-serif";

// now: the report explained as it stands (fixes get tested after it's first shown).
// project: { label, github } from the page. Returns the section's body.
export function shareParts(now, report, project, el, copy) {
  const e = now();
  const canvas = Object.assign(document.createElement("canvas"), { width: W, height: H });
  canvas.className = "share-preview";
  canvas.setAttribute("role", "img");
  const named = el("input", { type: "checkbox", checked: Boolean(project.github) && "ABC".includes(e.grade) });
  const nameRow = project.github ? [el("label", { className: "mt-3 flex items-center gap-2 text-[0.95rem]" }, named, `Show ${project.label} on it`)] : [];
  const draw = async () => {
    await draw.ready;
    paint(canvas, now(), report, named.checked && project.github ? project.label : null);
    canvas.setAttribute("aria-label", `Grade ${e.grade}: ${headline(e)}`);
  };
  draw.ready = Promise.all(["800 56px", "600 30px", "700 24px"].map((f) => document.fonts.load(`${f} 'Archivo Variable'`))).catch(() => {});
  named.addEventListener("change", draw);
  // Drawn again once the fixes are tested.
  canvas.redraw = draw;
  draw();

  const png = () => new Promise((resolve) => canvas.toBlob(resolve, "image/png"));
  const file = async () => new File([await png()], `rls-probe-grade-${e.grade}.png`, { type: "image/png" });
  const text = () => postText(now(), named.checked && project.github ? project : null);
  const buttons = el("div", { className: "mt-4 flex flex-wrap gap-3" });
  const download = el("button", { type: "button", className: "btn btn-ink" }, "Download the image");
  download.addEventListener("click", async () => {
    const a = el("a", { href: URL.createObjectURL(await png()), download: `rls-probe-grade-${e.grade}.png` });
    a.click();
    setTimeout(() => URL.revokeObjectURL(a.href), 1000);
  });
  buttons.append(download);
  if (window.ClipboardItem && navigator.clipboard?.write) {
    const copyImage = el("button", { type: "button", className: "btn btn-line" }, "Copy the image");
    copyImage.addEventListener("click", async () => {
      // Handing the clipboard a promise keeps Safari's user-gesture rule happy.
      await navigator.clipboard.write([new ClipboardItem({ "image/png": png() })]);
      copyImage.textContent = "Copied";
      setTimeout(() => (copyImage.textContent = "Copy the image"), 2000);
    });
    buttons.append(copyImage);
  }
  if (navigator.canShare?.({ files: [new File([""], "x.png", { type: "image/png" })] })) {
    const share = el("button", { type: "button", className: "btn btn-line" }, "Share…");
    share.addEventListener("click", async () => {
      try {
        await navigator.share({ files: [await file()], text: text().text, url: text().url });
      } catch {
        // Closed without sharing.
      }
    });
    buttons.append(share);
  }
  const x = el("button", { type: "button", className: "btn btn-line" }, "Post on X");
  x.addEventListener("click", () => {
    const { text: words, url } = text();
    window.open(`https://x.com/intent/post?text=${encodeURIComponent(words)}&url=${encodeURIComponent(url)}`, "_blank", "noopener");
  });
  buttons.append(x);
  const words = el("button", { type: "button", className: "btn btn-line" }, "Copy the words");
  words.addEventListener("click", () => copy(`${text().text} ${text().url}`, words, "Copy the words"));
  buttons.append(words);

  return [
    canvas,
    ...nameRow,
    buttons,
    el("p", { className: "mt-3 text-[0.9rem] text-muted" }, "The picture shows the grade and how many problems of each kind, never what they are. On X, attach the downloaded picture to the post."),
  ];
}

function headline(e) {
  const n = e.problems.length;
  if (e.grade === "A") return "Every user's data kept apart";
  if (e.grade === "B") return "No problems, a few things to check";
  return `${n} problem${n === 1 ? "" : "s"} found`;
}

function postText(e, project) {
  const app = project ? project.label : "my Supabase app";
  const n = e.problems.length;
  const url = project ? `${SITE}#repo=${project.github}` : SITE;
  if (e.grade === "A" || e.grade === "B") {
    return { text: `rls-probe inspected ${app}'s database: grade ${e.grade}. It signs in test users and tries to read and change each other's data, right in the browser.`, url };
  }
  const tested = e.problems.filter((p) => p.selfFix?.tested).length;
  const fixes = tested === n ? ", each with a fix it tested first" : tested ? `, ${tested} with a fix it tested first` : "";
  return { text: `rls-probe found ${n} security problem${n === 1 ? "" : "s"} in ${app}${fixes}. Fixing now. Check yours in a minute:`, url };
}

function paint(canvas, e, report, name) {
  const c = canvas.getContext("2d");
  const grade = e.grade ?? "?";
  const colour = GRADE[grade] ?? MUTED;
  c.fillStyle = PAPER;
  c.fillRect(0, 0, W, H);
  // A torn-off slip edge along the top, as on the page's result.
  c.fillStyle = "#fff3b8";
  c.fillRect(0, 0, W, 14);
  c.fillStyle = PAPER;
  for (let x = 7; x < W; x += 14) {
    c.beginPath();
    c.arc(x, 14, 4.5, 0, Math.PI * 2);
    c.fill();
  }

  // The grade card, tilted like the one on the page.
  c.save();
  c.translate(270, 330);
  c.rotate((-3 * Math.PI) / 180);
  const cw = 360;
  const ch = 430;
  box(c, -cw / 2, -ch / 2, cw, ch, 10, CARD, colour, 6);
  box(c, -cw / 2 + 14, -ch / 2 + 14, cw - 28, ch - 28, 6, null, colour, 3);
  c.fillStyle = colour;
  c.textAlign = "center";
  c.font = `700 30px ${FONT}`;
  c.fillText("Database inspection", 0, -ch / 2 + 70);
  c.font = `900 250px ${FONT}`;
  c.fillText(grade, 0, 95);
  c.fillStyle = MUTED;
  c.font = `500 24px ${FONT}`;
  const tables = report.results.length;
  c.fillText(`${tables} table${tables === 1 ? "" : "s"} checked`, 0, ch / 2 - 42);
  c.restore();

  // The words.
  const x = 520;
  c.textAlign = "left";
  let y = 150;
  if (name) {
    c.fillStyle = MUTED;
    c.font = `600 28px ${FONT}`;
    c.fillText(fit(c, name.replace(/^github\.com\//, ""), W - x - 60), x, y);
    y += 70;
  } else y += 30;
  c.fillStyle = INK;
  c.font = `800 60px ${FONT}`;
  for (const line of wrap(c, headline(e), W - x - 60)) {
    c.fillText(line, x, y);
    y += 68;
  }
  y += 10;
  // How many of each kind, as chips.
  let cx = x;
  const chips = SEVERITY.map(([key, word, ink]) => [e.problems.filter((p) => p.severity === key).length, word, ink]).filter(([n]) => n);
  if (e.notes.length) chips.push([e.notes.length, "worth a look", INK]);
  c.font = `700 24px ${FONT}`;
  for (const [n, word, ink] of chips) {
    const label = `${n} ${word}`;
    const w = c.measureText(label).width + 32;
    if (cx + w > W - 40) break;
    box(c, cx, y - 34, w, 48, 8, null, ink, 3);
    c.fillStyle = ink;
    c.fillText(label, cx + 16, y - 2);
    cx += w + 12;
  }
  if (chips.length) y += 56;
  // Only what's true: problems in the code have no database fix to test.
  const tested = e.problems.filter((p) => p.selfFix?.tested).length;
  if (tested) {
    c.fillStyle = TEXT;
    c.font = `500 26px ${FONT}`;
    c.fillText(`${tested === e.problems.length ? "Each" : `${tested} of ${e.problems.length}`} with a fix tested on a copy of the database`, x, y + 6);
  }

  // Signed, along the bottom.
  c.fillStyle = TEXT;
  c.font = `800 30px ${FONT}`;
  mark(c, x, H - 104);
  c.fillText("rls-probe", x + 56, H - 70);
  c.fillStyle = MUTED;
  c.font = `500 24px ${FONT}`;
  c.fillText("zkousama.github.io/rls-probe", x + 56, H - 38);
}

// The logo: a tilted card with one red row leaking out.
function mark(c, x, y) {
  c.save();
  c.translate(x + 22, y + 22);
  c.rotate((-8 * Math.PI) / 180);
  box(c, -20, -20, 40, 40, 7, "#fffdf6", INK, 4);
  c.fillStyle = INK;
  bar(c, -12, -11, 23);
  bar(c, -12, 5, 23);
  c.fillStyle = "#c2142d";
  bar(c, -12, -3, 37);
  c.restore();
}

function bar(c, x, y, w) {
  c.beginPath();
  c.roundRect(x, y, w, 5, 2.5);
  c.fill();
}

function box(c, x, y, w, h, r, fill, stroke, lineWidth) {
  c.beginPath();
  c.roundRect(x, y, w, h, r);
  if (fill) {
    c.fillStyle = fill;
    c.fill();
  }
  if (stroke) {
    c.strokeStyle = stroke;
    c.lineWidth = lineWidth;
    c.stroke();
  }
}

function wrap(c, text, width) {
  const lines = [""];
  for (const word of text.split(" ")) {
    const next = lines.at(-1) ? `${lines.at(-1)} ${word}` : word;
    if (c.measureText(next).width > width && lines.at(-1)) lines.push(word);
    else lines[lines.length - 1] = next;
  }
  return lines;
}

function fit(c, text, width) {
  if (c.measureText(text).width <= width) return text;
  let t = text;
  while (t.length > 4 && c.measureText(`…${t}`).width > width) t = t.slice(1);
  return `…${t}`;
}
