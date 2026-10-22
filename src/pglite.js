import { PGlite } from "@electric-sql/pglite";
import { pgcrypto } from "@electric-sql/pglite/contrib/pgcrypto";
import { uuid_ossp } from "@electric-sql/pglite/contrib/uuid_ossp";

// Every Supabase project has these two in schema extensions, and migrations call
// their functions without creating them.
export const PREINSTALLED = { pgcrypto, uuid_ossp };

// Supabase's search_path, so those functions resolve; and 16 MB of shared buffers
// rather than 128, since the whole database fits in a few megabytes.
export const START_PARAMS = [...PGlite.defaultStartParams, "-c", 'search_path="$user", public, extensions', "-c", "shared_buffers=16MB"];

// The other extensions PGlite ships, by their `create extension` name, loaded only
// when a migration creates one. Listed one by one so a bundler, or a browser's
// import map, can find each.
export const CONTRIB = {
  amcheck: () => import("@electric-sql/pglite/contrib/amcheck"),
  auto_explain: () => import("@electric-sql/pglite/contrib/auto_explain"),
  bloom: () => import("@electric-sql/pglite/contrib/bloom"),
  btree_gin: () => import("@electric-sql/pglite/contrib/btree_gin"),
  btree_gist: () => import("@electric-sql/pglite/contrib/btree_gist"),
  citext: () => import("@electric-sql/pglite/contrib/citext"),
  cube: () => import("@electric-sql/pglite/contrib/cube"),
  dict_int: () => import("@electric-sql/pglite/contrib/dict_int"),
  dict_xsyn: () => import("@electric-sql/pglite/contrib/dict_xsyn"),
  earthdistance: () => import("@electric-sql/pglite/contrib/earthdistance"),
  file_fdw: () => import("@electric-sql/pglite/contrib/file_fdw"),
  fuzzystrmatch: () => import("@electric-sql/pglite/contrib/fuzzystrmatch"),
  hstore: () => import("@electric-sql/pglite/contrib/hstore"),
  intarray: () => import("@electric-sql/pglite/contrib/intarray"),
  isn: () => import("@electric-sql/pglite/contrib/isn"),
  lo: () => import("@electric-sql/pglite/contrib/lo"),
  ltree: () => import("@electric-sql/pglite/contrib/ltree"),
  moddatetime: () => import("@electric-sql/pglite/contrib/moddatetime"),
  pageinspect: () => import("@electric-sql/pglite/contrib/pageinspect"),
  pg_buffercache: () => import("@electric-sql/pglite/contrib/pg_buffercache"),
  pg_freespacemap: () => import("@electric-sql/pglite/contrib/pg_freespacemap"),
  pg_stat_statements: () => import("@electric-sql/pglite/contrib/pg_stat_statements"),
  pg_surgery: () => import("@electric-sql/pglite/contrib/pg_surgery"),
  pg_trgm: () => import("@electric-sql/pglite/contrib/pg_trgm"),
  pg_visibility: () => import("@electric-sql/pglite/contrib/pg_visibility"),
  pg_walinspect: () => import("@electric-sql/pglite/contrib/pg_walinspect"),
  seg: () => import("@electric-sql/pglite/contrib/seg"),
  tablefunc: () => import("@electric-sql/pglite/contrib/tablefunc"),
  tcn: () => import("@electric-sql/pglite/contrib/tcn"),
  tsm_system_rows: () => import("@electric-sql/pglite/contrib/tsm_system_rows"),
  tsm_system_time: () => import("@electric-sql/pglite/contrib/tsm_system_time"),
  unaccent: () => import("@electric-sql/pglite/contrib/unaccent"),
};
