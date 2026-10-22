// Postgres dollar-quote tags: $$, $body$, $a2$ (a digit can't come first).
const DOLLAR = /\$([A-Za-z_][A-Za-z0-9_]*)?\$/y;

// Splits a SQL file into statements. Migrations from the Supabase CLI hold
// function bodies in dollar quotes, which a split on ";" would cut apart.
export function splitStatements(sql) {
  const out = [];
  let start = 0;
  let i = 0;
  // Whether the current statement has anything besides comments and whitespace.
  // Tracked while walking, in linear time: long comment headers are common.
  let code = false;
  const n = sql.length;
  while (i < n) {
    const c = sql[i];
    const next = sql[i + 1];
    if (c === "-" && next === "-") {
      const end = sql.indexOf("\n", i);
      i = end === -1 ? n : end + 1;
    } else if (c === "/" && next === "*") {
      const end = sql.indexOf("*/", i + 2);
      i = end === -1 ? n : end + 2;
    } else if (c === "'" || c === '"') {
      code = true;
      i++;
      while (i < n) {
        if (sql[i] === c && sql[i + 1] === c) i += 2;
        else if (sql[i] === c) { i++; break; }
        else i++;
      }
    } else if (c === "$") {
      code = true;
      DOLLAR.lastIndex = i;
      const m = DOLLAR.exec(sql);
      if (m) {
        const end = sql.indexOf(m[0], i + m[0].length);
        i = end === -1 ? n : end + m[0].length;
      } else i++;
    } else if (c === ";") {
      push(sql.slice(start, i));
      i++;
      start = i;
    } else {
      if (c !== " " && c !== "\n" && c !== "\t" && c !== "\r") code = true;
      i++;
    }
  }
  push(sql.slice(start));
  return out;

  function push(text) {
    if (code) out.push(text.trim());
    code = false;
  }
}
