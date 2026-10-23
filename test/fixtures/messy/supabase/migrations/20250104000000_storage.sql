-- A private documents bucket any signed-in user can read and upload into, a public
-- avatars bucket kept to each user's folder, and a receipts bucket made in the
-- dashboard that only its policies name.
insert into storage.buckets (id, name, public) values ('documents', 'documents', false), ('avatars', 'avatars', true);

create policy "signed-in users read documents" on storage.objects for select to authenticated
  using (bucket_id = 'documents');
create policy "signed-in users upload documents" on storage.objects for insert to authenticated
  with check (bucket_id = 'documents');

create policy "anyone views avatars" on storage.objects for select
  using (bucket_id = 'avatars');
create policy "users upload their own avatar" on storage.objects for insert to authenticated
  with check (bucket_id = 'avatars' and (storage.foldername(name))[1] = auth.uid()::text);

create policy "users manage their own receipts" on storage.objects for all to authenticated
  using (bucket_id = 'receipts' and (storage.foldername(name))[1] = auth.uid()::text)
  with check (bucket_id = 'receipts' and (storage.foldername(name))[1] = auth.uid()::text);
