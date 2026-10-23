import { supabase } from "../lib/supabase";
export async function send(message: string) {
  await supabase.from("contact_messages").insert({ message });
}
