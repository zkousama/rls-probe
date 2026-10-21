// Splits a SQL file into statements. Migrations from the Supabase CLI hold
// function bodies in dollar quotes, which a split on ";" would cut apart.
export function splitStatements(sql) {
  const out = [];
  let start = 0;
  let i = 0;
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
      i++;
      while (i < n) {
        if (sql[i] === c && sql[i + 1] === c) i += 2;
        else if (sql[i] === c) { i++; break; }
        else i++;
      }
    } else if (c === "$") {
      const m = /^\$[A-Za-z_]*\$/.exec(sql.slice(i));
      if (m) {
        const end = sql.indexOf(m[0], i + m[0].length);
        i = end === -1 ? n : end + m[0].length;
      } else i++;
    } else if (c === ";") {
      push(sql.slice(start, i));
      i++;
      start = i;
    } else i++;
  }
  push(sql.slice(start));
  return out;

  function push(text) {
    const trimmed = text.trim();
    if (trimmed && !/^(--[^\n]*\n?|\/\*[\s\S]*?\*\/|\s)*$/.test(trimmed)) out.push(trimmed);
  }
}
