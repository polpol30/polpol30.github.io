-- Run once in your Supabase project's SQL Editor. No passwords are stored here.
begin;

create table if not exists public.unihub_profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  name text not null default 'طالب جديد' check (char_length(btrim(name)) between 1 and 70),
  college text not null default '' check (char_length(college) <= 80),
  year text not null default 'الأولى' check (year in ('الأولى','الثانية','الثالثة','الرابعة','الخامسة')),
  skills text[] not null default '{}' check (cardinality(skills) <= 15 and char_length(skills::text) <= 1000),
  bio text not null default '' check (char_length(bio) <= 500),
  contact text not null default '' check (contact = '' or (contact ~ '^https?://' and char_length(contact) <= 1000)),
  available boolean not null default false,
  directory_visible boolean not null default false,
  created_at timestamptz not null default now(),
  updated_at timestamptz not null default now()
);

alter table public.unihub_profiles enable row level security;
revoke all on public.unihub_profiles from anon, authenticated;
grant select on public.unihub_profiles to authenticated;
grant insert (id,name,college,year,skills,bio,contact,available,directory_visible) on public.unihub_profiles to authenticated;
grant update (name,college,year,skills,bio,contact,available,directory_visible) on public.unihub_profiles to authenticated;

drop policy if exists "unihub_read_own_or_visible" on public.unihub_profiles;
create policy "unihub_read_own_or_visible" on public.unihub_profiles for select to authenticated
using (id = (select auth.uid()) or directory_visible = true);

drop policy if exists "unihub_insert_own" on public.unihub_profiles;
create policy "unihub_insert_own" on public.unihub_profiles for insert to authenticated
with check (id = (select auth.uid()));

drop policy if exists "unihub_update_own" on public.unihub_profiles;
create policy "unihub_update_own" on public.unihub_profiles for update to authenticated
using (id = (select auth.uid())) with check (id = (select auth.uid()));

create or replace function public.unihub_profile_timestamps()
returns trigger language plpgsql set search_path = '' as $$
begin
  new.updated_at = now();
  return new;
end;
$$;
revoke all on function public.unihub_profile_timestamps() from public, anon, authenticated;
drop trigger if exists unihub_profile_updated on public.unihub_profiles;
create trigger unihub_profile_updated before update on public.unihub_profiles
for each row execute function public.unihub_profile_timestamps();

create or replace function public.unihub_create_profile()
returns trigger language plpgsql security definer set search_path = '' as $$
begin
  insert into public.unihub_profiles(id,name)
  values (new.id,left(coalesce(nullif(btrim(new.raw_user_meta_data->>'full_name'),''),'طالب جديد'),70))
  on conflict (id) do nothing;
  return new;
end;
$$;
revoke all on function public.unihub_create_profile() from public, anon, authenticated;
drop trigger if exists unihub_auth_user_created on auth.users;
create trigger unihub_auth_user_created after insert on auth.users
for each row execute function public.unihub_create_profile();

-- Backfill people who signed up before this migration was installed.
insert into public.unihub_profiles(id,name)
select id,left(coalesce(nullif(btrim(raw_user_meta_data->>'full_name'),''),'طالب جديد'),70)
from auth.users on conflict (id) do nothing;

commit;
