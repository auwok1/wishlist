-- WishList database schema. Run this entire file in Supabase SQL Editor.
-- First enable Authentication -> Providers -> Anonymous Sign-Ins in the Supabase dashboard.
create extension if not exists pgcrypto;

create table if not exists public.profiles (
  user_id uuid primary key references auth.users(id) on delete cascade,
  display_name text not null check (char_length(display_name) between 1 and 40),
  created_at timestamptz not null default now()
);
create table if not exists public.groups (
  id uuid primary key default gen_random_uuid(),
  name text not null check (char_length(name) between 1 and 60),
  invite_code text not null unique default encode(gen_random_bytes(9), 'hex'),
  owner_id uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);
create table if not exists public.memberships (
  group_id uuid not null references public.groups(id) on delete cascade,
  user_id uuid not null references auth.users(id) on delete cascade,
  role text not null default 'member' check (role in ('owner','member')),
  joined_at timestamptz not null default now(),
  primary key (group_id,user_id)
);
create table if not exists public.wishes (
  id uuid primary key default gen_random_uuid(),
  group_id uuid not null references public.groups(id) on delete cascade,
  owner_id uuid not null references auth.users(id) on delete cascade,
  title text not null check (char_length(title) between 1 and 100),
  description text,
  image_path text,
  product_url text,
  created_at timestamptz not null default now()
);
create table if not exists public.reservations (
  wish_id uuid primary key references public.wishes(id) on delete cascade,
  reserver_id uuid not null references auth.users(id) on delete cascade,
  created_at timestamptz not null default now()
);
create index if not exists memberships_user_idx on public.memberships(user_id);
create index if not exists wishes_group_idx on public.wishes(group_id);

alter table public.profiles enable row level security;
alter table public.groups enable row level security;
alter table public.memberships enable row level security;
alter table public.wishes enable row level security;
alter table public.reservations enable row level security;

-- Profiles are visible to people in a shared group, but users edit only their own profile.
create policy "profiles_read_shared_group" on public.profiles for select to authenticated using (
  user_id = auth.uid() or exists (
    select 1 from public.memberships mine join public.memberships theirs on mine.group_id=theirs.group_id
    where mine.user_id=auth.uid() and theirs.user_id=profiles.user_id
  )
);
create policy "profiles_insert_self" on public.profiles for insert to authenticated with check (user_id=auth.uid());
create policy "profiles_update_self" on public.profiles for update to authenticated using (user_id=auth.uid()) with check (user_id=auth.uid());
create policy "groups_read_members" on public.groups for select to authenticated using (exists(select 1 from public.memberships m where m.group_id=id and m.user_id=auth.uid()));
create policy "groups_update_owner" on public.groups for update to authenticated using (owner_id=auth.uid()) with check (owner_id=auth.uid());
create policy "memberships_read_group" on public.memberships for select to authenticated using (exists(select 1 from public.memberships mine where mine.group_id=memberships.group_id and mine.user_id=auth.uid()));
create policy "wishes_read_group" on public.wishes for select to authenticated using (exists(select 1 from public.memberships m where m.group_id=wishes.group_id and m.user_id=auth.uid()));
create policy "wishes_insert_self_member" on public.wishes for insert to authenticated with check (owner_id=auth.uid() and exists(select 1 from public.memberships m where m.group_id=wishes.group_id and m.user_id=auth.uid()));
create policy "wishes_update_owner" on public.wishes for update to authenticated using (owner_id=auth.uid()) with check (owner_id=auth.uid());
create policy "wishes_delete_owner" on public.wishes for delete to authenticated using (owner_id=auth.uid() or exists(select 1 from public.groups g where g.id=wishes.group_id and g.owner_id=auth.uid()));
-- A wish owner cannot read their own reservation; all other group members can.
create policy "reservations_read_except_wish_owner" on public.reservations for select to authenticated using (
  reserver_id=auth.uid() or exists(
    select 1 from public.wishes w join public.memberships m on m.group_id=w.group_id
    where w.id=reservations.wish_id and m.user_id=auth.uid() and w.owner_id<>auth.uid()
  )
);

-- Functions below run with elevated privileges but verify the caller and group membership.
create or replace function public.create_group(p_name text,p_display_name text)
returns jsonb language plpgsql security definer set search_path=public,pg_temp as $$
declare g public.groups;
begin
  if auth.uid() is null then raise exception 'AUTH_REQUIRED'; end if;
  insert into profiles(user_id,display_name) values(auth.uid(),left(trim(p_display_name),40))
  on conflict(user_id) do update set display_name=excluded.display_name;
  insert into groups(name,owner_id) values(left(trim(p_name),60),auth.uid()) returning * into g;
  insert into memberships(group_id,user_id,role) values(g.id,auth.uid(),'owner');
  return jsonb_build_object('group_id',g.id,'invite_code',g.invite_code);
end; $$;

create or replace function public.join_group(p_invite_code text,p_display_name text)
returns jsonb language plpgsql security definer set search_path=public,pg_temp as $$
declare g public.groups; n integer;
begin
  if auth.uid() is null then raise exception 'AUTH_REQUIRED'; end if;
  select * into g from groups where invite_code=p_invite_code for update;
  if g.id is null then raise exception 'INVALID_INVITE'; end if;
  insert into profiles(user_id,display_name) values(auth.uid(),left(trim(p_display_name),40))
  on conflict(user_id) do update set display_name=excluded.display_name;
  if not exists(select 1 from memberships where group_id=g.id and user_id=auth.uid()) then
    select count(*) into n from memberships where group_id=g.id;
    if n>=25 then raise exception 'GROUP_FULL'; end if;
    insert into memberships(group_id,user_id,role) values(g.id,auth.uid(),'member');
  end if;
  return jsonb_build_object('group_id',g.id);
end; $$;

create or replace function public.reserve_wish(p_wish_id uuid)
returns void language plpgsql security definer set search_path=public,pg_temp as $$
declare w public.wishes;
begin
  if auth.uid() is null then raise exception 'AUTH_REQUIRED'; end if;
  select * into w from wishes where id=p_wish_id for update;
  if w.id is null then raise exception 'WISH_NOT_FOUND'; end if;
  if w.owner_id=auth.uid() then raise exception 'CANNOT_RESERVE_OWN_WISH'; end if;
  if not exists(select 1 from memberships where group_id=w.group_id and user_id=auth.uid()) then raise exception 'NOT_GROUP_MEMBER'; end if;
  insert into reservations(wish_id,reserver_id) values(p_wish_id,auth.uid());
exception when unique_violation then raise exception 'ALREADY_RESERVED';
end; $$;

create or replace function public.unreserve_wish(p_wish_id uuid)
returns void language plpgsql security definer set search_path=public,pg_temp as $$
begin
  delete from reservations where wish_id=p_wish_id and reserver_id=auth.uid();
  if not found then raise exception 'NOT_YOUR_RESERVATION'; end if;
end; $$;

create or replace function public.remove_group_member(p_group_id uuid,p_user_id uuid)
returns void language plpgsql security definer set search_path=public,pg_temp as $$
begin
  if not exists(select 1 from groups where id=p_group_id and owner_id=auth.uid()) then raise exception 'OWNER_ONLY'; end if;
  if p_user_id=auth.uid() then raise exception 'CANNOT_REMOVE_OWNER'; end if;
  delete from memberships where group_id=p_group_id and user_id=p_user_id;
  delete from wishes where group_id=p_group_id and owner_id=p_user_id;
end; $$;

create or replace function public.delete_group(p_group_id uuid)
returns void language plpgsql security definer set search_path=public,pg_temp as $$
begin
  delete from groups where id=p_group_id and owner_id=auth.uid();
  if not found then raise exception 'OWNER_ONLY'; end if;
end; $$;

revoke all on function public.create_group(text,text) from public;
revoke all on function public.join_group(text,text) from public;
revoke all on function public.reserve_wish(uuid) from public;
revoke all on function public.unreserve_wish(uuid) from public;
revoke all on function public.remove_group_member(uuid,uuid) from public;
revoke all on function public.delete_group(uuid) from public;
grant execute on function public.create_group(text,text) to authenticated;
grant execute on function public.join_group(text,text) to authenticated;
grant execute on function public.reserve_wish(uuid) to authenticated;
grant execute on function public.unreserve_wish(uuid) to authenticated;
grant execute on function public.remove_group_member(uuid,uuid) to authenticated;
grant execute on function public.delete_group(uuid) to authenticated;

-- Private bucket: photos are delivered through signed URLs in the app's production version.
insert into storage.buckets(id,name,public,file_size_limit,allowed_mime_types)
values('wish-photos','wish-photos',true,5242880,array['image/jpeg','image/png','image/webp'])
on conflict(id) do nothing;
create policy "group members upload wish photos" on storage.objects for insert to authenticated with check (
  bucket_id='wish-photos' and exists(select 1 from public.memberships m where m.group_id=(storage.foldername(name))[1]::uuid and m.user_id=auth.uid())
);
create policy "group members read wish photos" on storage.objects for select to authenticated using (
  bucket_id='wish-photos' and exists(select 1 from public.memberships m where m.group_id=(storage.foldername(name))[1]::uuid and m.user_id=auth.uid())
);
create policy "photo owner deletes own uploads" on storage.objects for delete to authenticated using (
  bucket_id='wish-photos' and (storage.foldername(name))[2]=auth.uid()::text
);
