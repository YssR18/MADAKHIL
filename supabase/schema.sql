-- مداخيل المحل: schema, roles (manager / observer / pending) and row level security

create table public.profiles (
  id uuid primary key references auth.users(id) on delete cascade,
  email text,
  role text not null default 'pending' check (role in ('pending', 'observer', 'manager')),
  created_at timestamptz not null default now()
);

create table public.entries (
  id text primary key check (id ~ '^[A-Za-z0-9_-]{1,60}$'),
  entry_date date not null,
  amount numeric(14,2) not null check (amount > 0),
  note text not null default '' check (char_length(note) <= 500),
  transferred boolean not null default false,
  created_at timestamptz not null default now()
);
create index entries_entry_date_idx on public.entries (entry_date desc);

create table public.batches (
  id text primary key check (id ~ '^[A-Za-z0-9_-]{1,60}$'),
  start_date date,
  end_date date,
  total_amount numeric(14,2) not null default 0,
  entries_count integer not null default 0,
  entry_ids text[] not null default '{}',
  created_at timestamptz not null default now()
);

alter table public.profiles enable row level security;
alter table public.entries enable row level security;
alter table public.batches enable row level security;

-- the current user's role (security definer so policies can use it without recursion)
create or replace function public.app_role()
returns text
language sql
stable
security definer
set search_path = public
as $$
  select role from public.profiles where id = auth.uid()
$$;
revoke all on function public.app_role() from public, anon;
grant execute on function public.app_role() to authenticated;

-- every new account gets a profile: the very first one becomes the manager, everyone else waits for approval
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  perform pg_advisory_xact_lock(871001);
  insert into public.profiles (id, email, role)
  values (
    new.id,
    new.email,
    case when exists (select 1 from public.profiles where role = 'manager') then 'pending' else 'manager' end
  );
  return new;
end
$$;
revoke all on function public.handle_new_user() from public, anon, authenticated;

create trigger on_auth_user_created
  after insert on auth.users
  for each row execute function public.handle_new_user();

-- never leave the shop without a manager
create or replace function public.keep_one_manager()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  if old.role = 'manager' and new.role <> 'manager'
     and not exists (select 1 from public.profiles where role = 'manager' and id <> old.id) then
    raise exception 'لا يمكن إزالة آخر مدير';
  end if;
  return new;
end
$$;
revoke all on function public.keep_one_manager() from public, anon, authenticated;

create trigger profiles_keep_one_manager
  before update on public.profiles
  for each row execute function public.keep_one_manager();

-- privileges: signed-out visitors get nothing; signed-in users are limited by the policies below
revoke all on public.profiles, public.entries, public.batches from anon, authenticated;
grant select on public.profiles, public.entries, public.batches to authenticated;
grant update (role) on public.profiles to authenticated;
grant insert, update, delete on public.entries, public.batches to authenticated;

-- profiles: see your own, the manager sees everyone and changes roles
create policy profiles_select on public.profiles for select to authenticated
  using (id = (select auth.uid()) or (select public.app_role()) = 'manager');
create policy profiles_update on public.profiles for update to authenticated
  using ((select public.app_role()) = 'manager')
  with check ((select public.app_role()) = 'manager');

-- income entries and weekly batches: manager and observer read, only the manager writes
create policy entries_select on public.entries for select to authenticated
  using ((select public.app_role()) in ('manager', 'observer'));
create policy entries_insert on public.entries for insert to authenticated
  with check ((select public.app_role()) = 'manager');
create policy entries_update on public.entries for update to authenticated
  using ((select public.app_role()) = 'manager')
  with check ((select public.app_role()) = 'manager');
create policy entries_delete on public.entries for delete to authenticated
  using ((select public.app_role()) = 'manager');

create policy batches_select on public.batches for select to authenticated
  using ((select public.app_role()) in ('manager', 'observer'));
create policy batches_insert on public.batches for insert to authenticated
  with check ((select public.app_role()) = 'manager');
create policy batches_update on public.batches for update to authenticated
  using ((select public.app_role()) = 'manager')
  with check ((select public.app_role()) = 'manager');
create policy batches_delete on public.batches for delete to authenticated
  using ((select public.app_role()) = 'manager');

-- ===== المراقب بلا كلمة سر + مدير واحد فقط =====
-- زائر بلا حساب يقرأ فقط (لا كتابة). يعني أن أي شخص لديه الرابط يرى المداخيل.
grant select on public.entries, public.batches to anon;
create policy entries_select_anon on public.entries for select to anon using (true);
create policy batches_select_anon on public.batches for select to anon using (true);

-- بعد إنشاء المدير الأول يُغلق التسجيل
create or replace function public.handle_new_user()
returns trigger
language plpgsql
security definer
set search_path = public
as $$
begin
  perform pg_advisory_xact_lock(871001);
  if exists (select 1 from public.profiles where role = 'manager') then
    raise exception 'التسجيل مغلق: يوجد مدير بالفعل';
  end if;
  insert into public.profiles (id, email, role) values (new.id, new.email, 'manager');
  return new;
end
$$;
revoke all on function public.handle_new_user() from public, anon, authenticated;

-- هل يوجد مدير؟ (تُستعمل لإخفاء «إنشاء حساب المدير» بعد إنشائه)
create or replace function public.manager_exists()
returns boolean language sql stable security definer set search_path = public
as $$ select exists (select 1 from public.profiles where role = 'manager') $$;
revoke all on function public.manager_exists() from public;
grant execute on function public.manager_exists() to anon, authenticated;
