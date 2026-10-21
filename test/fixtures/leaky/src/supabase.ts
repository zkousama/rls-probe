import { createClient } from "@supabase/supabase-js";
// someone pasted the service role key to get past a permissions error
const key = "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJpc3MiOiJzdXBhYmFzZSIsInJvbGUiOiJzZXJ2aWNlX3JvbGUiLCJpYXQiOjE3MDAwMDAwMDB9.c2lnbmF0dXJlLW5vdC1yZWFsLWZvci10ZXN0cw";
export const supabase = createClient(import.meta.env.VITE_SUPABASE_URL, key);
