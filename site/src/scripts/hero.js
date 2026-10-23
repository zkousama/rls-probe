// The grade card at the top: it climbs from F to A, the way an app's grade does as its
// problems get fixed, so it's clear F isn't the only grade there is. The scale under it
// shows each grade on demand. Still for anyone who'd rather not see motion.
const GRADES = [
  ["F", "Orders open to anyone"],
  ["D", "Users read each other's messages"],
  ["C", "Rows added in someone else's name"],
  ["B", "A few things worth a look"],
  ["A", "Every user kept apart"],
];

const card = document.getElementById("hero-card");
const scale = [...document.querySelectorAll("#hero-scale button")];
const still = matchMedia("(prefers-reduced-motion: reduce)").matches;
let at = 0;
let paused = false;

function show(i) {
  at = i;
  const [grade, sub] = GRADES[i];
  card.className = card.className.replace(/grade-\w+/, `grade-${grade}`).replace(/\s*stamp/, "");
  // Reading a size restarts the stamp animation on the same element.
  void card.offsetWidth;
  card.classList.add("stamp");
  card.querySelector(".p-letter").textContent = grade;
  card.querySelector(".p-sub").textContent = sub;
  for (const [j, b] of scale.entries()) b.setAttribute("aria-pressed", String(j === i));
}

for (const [i, b] of scale.entries()) b.addEventListener("click", () => show(i));
for (const el of [card, ...scale]) {
  el.addEventListener("pointerenter", () => (paused = true));
  el.addEventListener("pointerleave", () => (paused = false));
}
if (!still) setInterval(() => !paused && !document.hidden && show((at + 1) % GRADES.length), 2600);
