import { supabase } from "../lib/supabase";
export async function loadFeed() {
  const { data } = await supabase.from("posts").select("id, title").order("title")
  return data
}
