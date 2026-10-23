import { supabase } from "../lib/supabase";
export async function loadNotes() {
  const { data: { user } } = await supabase.auth.getUser();
  const { data } = await supabase.from("notes").select("*").eq("user_id", user!.id);
  return data;
}
