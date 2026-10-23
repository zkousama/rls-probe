import postgres from "postgres";
const sql = postgres(process.env.DATABASE_URL!);
export const signups = () => sql`SELECT day, signups FROM legacy_stats ORDER BY day`;
