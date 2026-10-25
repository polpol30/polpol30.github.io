-- UniHub shared content. Requires auth-setup.sql. No existing local data is deleted.
begin;
create table if not exists public.unihub_teams (
 id uuid primary key default gen_random_uuid(), owner_id uuid not null references auth.users(id) on delete cascade,
 title text not null check(char_length(btrim(title)) between 1 and 100), description text not null check(char_length(btrim(description)) between 1 and 1200),
 category text not null check(char_length(category) between 1 and 80), skills text[] not null check(cardinality(skills) between 1 and 15 and char_length(skills::text)<=1000),
 capacity integer not null check(capacity between 2 and 30), status text not null default 'مفتوح' check(status in ('مفتوح','مكتمل','مغلق')), created_at timestamptz not null default now()
);
create table if not exists public.unihub_members (
 team_id uuid not null references public.unihub_teams(id) on delete cascade, user_id uuid not null references auth.users(id) on delete cascade, primary key(team_id,user_id)
);
create table if not exists public.unihub_requests (
 id uuid primary key default gen_random_uuid(), team_id uuid not null references public.unihub_teams(id) on delete cascade,
 user_id uuid not null references auth.users(id) on delete cascade, message text not null check(char_length(btrim(message)) between 1 and 700),
 status text not null default 'pending' check(status in ('pending','accepted','rejected')), created_at timestamptz not null default now(), unique(team_id,user_id)
);
create table if not exists public.unihub_resources (
 id uuid primary key default gen_random_uuid(), owner_id uuid not null references auth.users(id) on delete cascade,
 title text not null check(char_length(btrim(title)) between 1 and 140), description text not null check(char_length(btrim(description)) between 1 and 700),
 college text not null check(char_length(btrim(college)) between 1 and 80), subject text not null check(char_length(btrim(subject)) between 1 and 100),
 year text not null check(year in ('الأولى','الثانية','الثالثة','الرابعة','الخامسة')), term text not null check(term in ('الأول','الثاني')),
 type text not null check(type in ('ملخص','امتحان سابق','مشروع تخرج','مرجع')),
 url text not null check(char_length(url)<=2000 and url ~ '^https?://[^/@[:space:]]+([/?#][^[:space:]]*)?$'),
 status text not null default 'published' check(status in ('published','hidden')), created_at timestamptz not null default now()
);
create table if not exists public.unihub_favorites (
 user_id uuid not null references auth.users(id) on delete cascade, resource_id uuid not null references public.unihub_resources(id) on delete cascade, primary key(user_id,resource_id)
);
create table if not exists public.unihub_opens (
 user_id uuid not null references auth.users(id) on delete cascade, resource_id uuid not null references public.unihub_resources(id) on delete cascade, primary key(user_id,resource_id)
);
create table if not exists public.unihub_reports (
 id uuid primary key default gen_random_uuid(), user_id uuid not null references auth.users(id) on delete cascade, resource_id uuid not null references public.unihub_resources(id) on delete cascade,
 reason text not null check(char_length(reason) between 1 and 100), details text not null check(char_length(btrim(details)) between 1 and 500),
 status text not null default 'open' check(status in ('open','resolved')), created_at timestamptz not null default now()
);
create unique index if not exists unihub_open_report on public.unihub_reports(user_id,resource_id) where status='open';
create table if not exists public.unihub_bookings (
 id uuid primary key default gen_random_uuid(), user_id uuid not null references auth.users(id) on delete cascade,
 event text not null check(event in ('ورشة UI/UX','تجارب أداء العرض المسرحي السنوي','ورشة كتابة النص المسرحي','معرض التصاميم والهوية البصرية')),
 name text not null check(char_length(btrim(name)) between 1 and 80), phone text not null check(phone ~ '^[+0-9[:space:]()٠-٩-]{7,24}$'),
 created_at timestamptz not null default now(), unique(user_id,event)
);
create index if not exists unihub_teams_owner on public.unihub_teams(owner_id);
create index if not exists unihub_resources_owner on public.unihub_resources(owner_id);
create index if not exists unihub_requests_user on public.unihub_requests(user_id);
create index if not exists unihub_members_user on public.unihub_members(user_id);
create index if not exists unihub_bookings_event on public.unihub_bookings(event);

-- Direct writes are not granted: the mutation function owns all invariants.
do $$ declare t text; begin
 foreach t in array array['unihub_teams','unihub_members','unihub_requests','unihub_resources','unihub_favorites','unihub_opens','unihub_reports','unihub_bookings'] loop
 execute format('alter table public.%I enable row level security',t);
 execute format('revoke all on public.%I from anon, authenticated',t);
 end loop;
end $$;
grant select on public.unihub_teams, public.unihub_members, public.unihub_requests, public.unihub_resources, public.unihub_favorites, public.unihub_reports, public.unihub_bookings to authenticated;
create policy unihub_team_read on public.unihub_teams for select to authenticated using(true);
create policy unihub_member_read on public.unihub_members for select to authenticated using(true);
create policy unihub_request_read on public.unihub_requests for select to authenticated using(user_id=(select auth.uid()) or exists(select 1 from public.unihub_teams t where t.id=team_id and t.owner_id=(select auth.uid())));
create policy unihub_resource_read on public.unihub_resources for select to authenticated using(status='published' or owner_id=(select auth.uid()));
create policy unihub_favorite_read on public.unihub_favorites for select to authenticated using(user_id=(select auth.uid()));
create policy unihub_booking_read on public.unihub_bookings for select to authenticated using(user_id=(select auth.uid()));
create policy unihub_report_read on public.unihub_reports for select to authenticated using(user_id=(select auth.uid()) or exists(select 1 from public.unihub_resources r where r.id=resource_id and r.owner_id=(select auth.uid())));

-- Security definer is used for atomic capacity enforcement and a filtered
-- snapshot with author display names; no private profile/contact fields leak.
create or replace function public.unihub_snapshot()
returns jsonb language plpgsql security definer set search_path='' as $$
declare u uuid:=auth.uid(); result jsonb;
begin
 if u is null or not exists(select 1 from auth.users where id=u and email_confirmed_at is not null) then raise exception 'unauthorized'; end if;
 select jsonb_build_object(
 'teams',coalesce((select jsonb_agg(item order by created_at desc) from (
   select t.created_at,jsonb_build_object('id',t.id,'owner',t.owner_id,'ownerName',coalesce(p.name,'طالب'),'title',t.title,'description',t.description,'category',t.category,'skills',t.skills,'capacity',t.capacity,'status',t.status,
   'members',coalesce((select jsonb_agg(m.user_id) from public.unihub_members m where m.team_id=t.id),'[]'::jsonb),
   'memberNames',coalesce((select jsonb_object_agg(m.user_id,coalesce(p2.name,'طالب')) from public.unihub_members m left join public.unihub_profiles p2 on p2.id=m.user_id where m.team_id=t.id),'{}'::jsonb)) item
   from public.unihub_teams t left join public.unihub_profiles p on p.id=t.owner_id order by t.created_at desc limit 500) q),'[]'::jsonb),
 'resources',coalesce((select jsonb_agg(item order by created_at desc) from (
   select r.created_at,jsonb_build_object('id',r.id,'owner',r.owner_id,'ownerName',coalesce(p.name,'طالب'),'title',r.title,'description',r.description,'college',r.college,'subject',r.subject,'year',r.year,'term',r.term,'type',r.type,'url',r.url,'status',r.status,'opens',(select count(*) from public.unihub_opens o where o.resource_id=r.id)) item
   from public.unihub_resources r left join public.unihub_profiles p on p.id=r.owner_id where r.status='published' or r.owner_id=u order by r.created_at desc limit 500) q),'[]'::jsonb),
 'requests',coalesce((select jsonb_agg(jsonb_build_object('id',r.id,'team',r.team_id,'user',r.user_id,'userName',coalesce(p.name,'طالب'),'message',r.message,'status',r.status))
   from public.unihub_requests r join public.unihub_teams t on t.id=r.team_id left join public.unihub_profiles p on p.id=r.user_id where r.user_id=u or t.owner_id=u),'[]'::jsonb),
 'bookings',coalesce((select jsonb_agg(jsonb_build_object('id',b.id,'user',b.user_id,'event',b.event,'name',b.name,'phone',b.phone,'date',b.created_at)) from public.unihub_bookings b where b.user_id=u),'[]'::jsonb),
 'reports',coalesce((select jsonb_agg(jsonb_build_object('id',f.id,'resource',f.resource_id,'user',f.user_id,'reason',f.reason,'details',f.details,'status',f.status)) from public.unihub_reports f join public.unihub_resources r on r.id=f.resource_id where f.user_id=u or r.owner_id=u),'[]'::jsonb),
 'favorites',coalesce((select jsonb_agg(f.resource_id) from public.unihub_favorites f join public.unihub_resources r on r.id=f.resource_id where f.user_id=u and (r.status='published' or r.owner_id=u)),'[]'::jsonb),
 'bookingCounts',coalesce((select jsonb_object_agg(event,total) from (select event,count(*) total from public.unihub_bookings group by event) c),'{}'::jsonb)
 ) into result;
 return result;
end $$;

create or replace function public.unihub_mutate(action_name text,payload jsonb default '{}')
returns jsonb language plpgsql security definer set search_path='' as $$
declare u uuid:=auth.uid(); ident uuid; team public.unihub_teams%rowtype; resource public.unihub_resources%rowtype; req public.unihub_requests%rowtype;
 owner uuid; skills_array text[]; n integer; event_name text; item jsonb; count_import integer:=0;
begin
 if u is null or not exists(select 1 from auth.users where id=u and email_confirmed_at is not null) then raise exception 'unauthorized'; end if;
 if payload is null or jsonb_typeof(payload)<>'object' or octet_length(payload::text)>1000000 then raise exception 'invalid_input'; end if;
 case action_name
 when 'save_team' then
   ident:=coalesce(nullif(payload->>'id','')::uuid,gen_random_uuid());
   select * into team from public.unihub_teams where id=ident for update;
   if found and team.owner_id<>u then raise exception 'forbidden'; end if;
   if payload ? 'owner' and (payload->>'owner')::uuid<>u then raise exception 'forbidden'; end if;
   n:=(payload->>'capacity')::integer;
   if n<(select count(*) from public.unihub_members where team_id=ident) then raise exception 'capacity_below_members'; end if;
   select array_agg(btrim(v)) into skills_array from jsonb_array_elements_text(payload->'skills') v;
   if team.id is null then
     insert into public.unihub_teams(id,owner_id,title,description,category,skills,capacity,status) values(ident,u,btrim(payload->>'title'),btrim(payload->>'description'),payload->>'category',skills_array,n,coalesce(payload->>'status','مفتوح'));
     insert into public.unihub_members(team_id,user_id) values(ident,u);
   else
     update public.unihub_teams set title=btrim(payload->>'title'),description=btrim(payload->>'description'),category=payload->>'category',skills=skills_array,capacity=n,status=payload->>'status' where id=ident;
   end if;
 when 'delete_team' then
   ident:=(payload->>'id')::uuid;
   delete from public.unihub_teams where id=ident and owner_id=u;
   if not found then raise exception 'forbidden'; end if;
 when 'apply' then
   ident:=(payload->>'team')::uuid;select * into team from public.unihub_teams where id=ident for update;
   if not found or team.owner_id=u or exists(select 1 from public.unihub_members where team_id=ident and user_id=u) then raise exception 'forbidden'; end if;
   if team.status<>'مفتوح' or (select count(*) from public.unihub_members where team_id=ident)>=team.capacity then raise exception 'team_full'; end if;
   insert into public.unihub_requests(team_id,user_id,message) values(ident,u,btrim(payload->>'message'));
 when 'decide_request' then
   ident:=(payload->>'id')::uuid;
   select t.* into team from public.unihub_teams t join public.unihub_requests r on r.team_id=t.id where r.id=ident for update of t;
   if not found or team.owner_id<>u then raise exception 'forbidden'; end if;
   select * into req from public.unihub_requests where id=ident for update;
   if req.status<>'pending' then raise exception 'request_already_decided'; end if;
   if coalesce((payload->>'accept')::boolean,false) then
     if team.status<>'مفتوح' or (select count(*) from public.unihub_members where team_id=team.id)>=team.capacity then raise exception 'team_full'; end if;
     insert into public.unihub_members(team_id,user_id) values(team.id,req.user_id) on conflict do nothing;
     update public.unihub_requests set status='accepted' where id=ident;
   else update public.unihub_requests set status='rejected' where id=ident;
   end if;
 when 'cancel_request' then
   delete from public.unihub_requests where id=(payload->>'id')::uuid and user_id=u and status='pending';
   if not found then raise exception 'forbidden'; end if;
 when 'save_resource' then
   ident:=coalesce(nullif(payload->>'id','')::uuid,gen_random_uuid());select * into resource from public.unihub_resources where id=ident for update;
   if found and resource.owner_id<>u then raise exception 'forbidden'; end if;
   if payload ? 'owner' and (payload->>'owner')::uuid<>u then raise exception 'forbidden'; end if;
   if resource.id is null then
     insert into public.unihub_resources(id,owner_id,title,description,college,subject,year,term,type,url) values(ident,u,btrim(payload->>'title'),btrim(payload->>'description'),btrim(payload->>'college'),btrim(payload->>'subject'),payload->>'year',payload->>'term',payload->>'type',payload->>'url');
   else update public.unihub_resources set title=btrim(payload->>'title'),description=btrim(payload->>'description'),college=btrim(payload->>'college'),subject=btrim(payload->>'subject'),year=payload->>'year',term=payload->>'term',type=payload->>'type',url=payload->>'url' where id=ident;
   end if;
 when 'delete_resource' then
   delete from public.unihub_resources where id=(payload->>'id')::uuid and owner_id=u;
   if not found then raise exception 'forbidden'; end if;
 when 'resource_visibility' then
   update public.unihub_resources set status=case when (payload->>'published')::boolean then 'published' else 'hidden' end where id=(payload->>'id')::uuid and owner_id=u;
   if not found then raise exception 'forbidden'; end if;
 when 'favorite' then
   ident:=(payload->>'id')::uuid;
   if not exists(select 1 from public.unihub_resources where id=ident and (status='published' or owner_id=u)) then raise exception 'forbidden'; end if;
   if (payload->>'saved')::boolean then insert into public.unihub_favorites(user_id,resource_id) values(u,ident) on conflict do nothing;
   else delete from public.unihub_favorites where user_id=u and resource_id=ident; end if;
 when 'open_resource' then
   ident:=(payload->>'id')::uuid;
   if not exists(select 1 from public.unihub_resources where id=ident and (status='published' or owner_id=u)) then raise exception 'forbidden'; end if;
   insert into public.unihub_opens(user_id,resource_id) values(u,ident) on conflict do nothing;
 when 'report' then
   ident:=(payload->>'resource')::uuid;
   if not exists(select 1 from public.unihub_resources where id=ident and (status='published' or owner_id=u)) then raise exception 'forbidden'; end if;
   insert into public.unihub_reports(user_id,resource_id,reason,details) values(u,ident,payload->>'reason',btrim(payload->>'details'));
 when 'resolve_report' then
   update public.unihub_reports f set status='resolved' from public.unihub_resources r where f.id=(payload->>'id')::uuid and r.id=f.resource_id and r.owner_id=u;
   if not found then raise exception 'forbidden'; end if;
 when 'book' then
   event_name:=coalesce(payload->>'event','ورشة UI/UX');
   perform pg_advisory_xact_lock(hashtext('unihub.booking.'||event_name));
   if (select count(*) from public.unihub_bookings where event=event_name)>=60 then raise exception 'event_full'; end if;
   insert into public.unihub_bookings(user_id,event,name,phone) values(u,event_name,btrim(payload->>'name'),btrim(payload->>'phone'));
 when 'cancel_booking' then
   delete from public.unihub_bookings where id=(payload->>'id')::uuid and user_id=u;
   if not found then raise exception 'forbidden'; end if;
 when 'import_owned' then
   if jsonb_array_length(coalesce(payload->'teams','[]'))+jsonb_array_length(coalesce(payload->'resources','[]'))+jsonb_array_length(coalesce(payload->'bookings','[]'))>200 then raise exception 'import_too_large'; end if;
   for item in select value from jsonb_array_elements(coalesce(payload->'teams','[]')) loop
     if (item->>'owner')::uuid is distinct from u then raise exception 'forbidden'; end if;
     if not exists(select 1 from public.unihub_teams where id=(item->>'id')::uuid) then perform public.unihub_mutate('save_team',item);count_import:=count_import+1;end if;
   end loop;
   for item in select value from jsonb_array_elements(coalesce(payload->'resources','[]')) loop
     if (item->>'owner')::uuid is distinct from u then raise exception 'forbidden'; end if;
     if not exists(select 1 from public.unihub_resources where id=(item->>'id')::uuid) then perform public.unihub_mutate('save_resource',item);count_import:=count_import+1;end if;
   end loop;
   for item in select value from jsonb_array_elements(coalesce(payload->'bookings','[]')) loop
     if (item->>'user')::uuid is distinct from u then raise exception 'forbidden'; end if;
     if not exists(select 1 from public.unihub_bookings where user_id=u and event=coalesce(item->>'event','ورشة UI/UX')) then perform public.unihub_mutate('book',item);count_import:=count_import+1;end if;
   end loop;
   if jsonb_array_length(coalesce(payload->'favorites','[]'))>500 then raise exception 'import_too_large'; end if;
   for item in select value from jsonb_array_elements(coalesce(payload->'favorites','[]')) loop
     ident:=trim(both '"' from item::text)::uuid;
     if exists(select 1 from public.unihub_resources where id=ident and (status='published' or owner_id=u)) then
       insert into public.unihub_favorites(user_id,resource_id) values(u,ident) on conflict do nothing;
     end if;
   end loop;
   return jsonb_build_object('ok',true,'imported',count_import);
 else raise exception 'unknown_action';
 end case;
 return jsonb_build_object('ok',true);
end $$;
revoke all on function public.unihub_snapshot() from public,anon,authenticated;
revoke all on function public.unihub_mutate(text,jsonb) from public,anon,authenticated;
grant execute on function public.unihub_snapshot(),public.unihub_mutate(text,jsonb) to authenticated;
notify pgrst,'reload schema';
commit;
