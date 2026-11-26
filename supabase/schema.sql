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

-- ===== المصاريف =====
create table public.expenses (
  id text primary key check (id ~ '^[A-Za-z0-9_-]{1,60}$'),
  expense_date date not null,
  amount numeric not null check (amount > 0),
  category text not null default '' check (char_length(category) <= 60),
  note text not null default '' check (char_length(note) <= 500),
  created_at timestamptz not null default now()
);
alter table public.expenses enable row level security;
revoke all on public.expenses from anon, authenticated;
grant select on public.expenses to anon;
grant select, insert, update, delete on public.expenses to authenticated;
create policy expenses_select_anon on public.expenses for select to anon using (true);
create policy expenses_select on public.expenses for select to authenticated
  using ((select public.app_role()) in ('manager', 'observer'));
create policy expenses_insert on public.expenses for insert to authenticated
  with check ((select public.app_role()) = 'manager');
create policy expenses_update on public.expenses for update to authenticated
  using ((select public.app_role()) = 'manager') with check ((select public.app_role()) = 'manager');
create policy expenses_delete on public.expenses for delete to authenticated
  using ((select public.app_role()) = 'manager');

-- ===== Orders + observer PIN =====
-- ===== الطلبات + رمز المراقب =====
create table public.orders (
  id text primary key check (id ~ '^[A-Za-z0-9_-]{1,60}$'),
  no integer not null check (no > 0),
  order_date date not null,
  status text not null check (status in ('new', 'ready', 'approved')),
  requester text not null default '' check (char_length(requester) <= 60),
  lines jsonb not null default '[]' check (jsonb_typeof(lines) = 'array' and jsonb_array_length(lines) <= 100),
  corrected boolean not null default false,
  approved_at date,
  created_at timestamptz not null default now()
);
alter table public.orders enable row level security;
revoke all on public.orders from anon, authenticated;
grant select on public.orders to anon;
grant select, insert, update, delete on public.orders to authenticated;
create policy orders_select_anon on public.orders for select to anon using (true);
create policy orders_select on public.orders for select to authenticated
  using ((select public.app_role()) in ('manager', 'observer'));
create policy orders_insert on public.orders for insert to authenticated
  with check ((select public.app_role()) = 'manager');
create policy orders_update on public.orders for update to authenticated
  using ((select public.app_role()) = 'manager') with check ((select public.app_role()) = 'manager');
create policy orders_delete on public.orders for delete to authenticated
  using ((select public.app_role()) = 'manager');

-- أسرار التطبيق: لا يصلها أحد من الواجهة، فقط الدوال أدناه
create table public.app_secrets (key text primary key, value text not null);
alter table public.app_secrets enable row level security;
revoke all on public.app_secrets from anon, authenticated;

-- التحقق من رمز المراقب مع قفل 10 دقائق بعد 5 محاولات فاشلة
create or replace function public._verify_pin(p text)
returns boolean
language plpgsql
security definer
set search_path = public, extensions
as $$
declare h text; locked timestamptz; fails int;
begin
  select value into h from app_secrets where key = 'observer_pin_hash';
  if h is null or p is null then return false; end if;
  select value::timestamptz into locked from app_secrets where key = 'pin_locked_until';
  if locked is not null and locked > now() then
    raise exception 'locked';
  end if;
  if crypt(p, h) = h then
    delete from app_secrets where key in ('pin_fail_count', 'pin_locked_until');
    return true;
  end if;
  select coalesce((select value::int from app_secrets where key = 'pin_fail_count'), 0) + 1 into fails;
  if fails >= 5 then
    insert into app_secrets values ('pin_locked_until', (now() + interval '10 minutes')::text)
      on conflict (key) do update set value = excluded.value;
    delete from app_secrets where key = 'pin_fail_count';
  else
    insert into app_secrets values ('pin_fail_count', fails::text)
      on conflict (key) do update set value = excluded.value;
  end if;
  return false;
end
$$;
revoke all on function public._verify_pin(text) from public, anon, authenticated;

create or replace function public.check_observer_pin(p text)
returns boolean language sql security definer set search_path = public
as $$ select public._verify_pin(p) $$;
revoke all on function public.check_observer_pin(text) from public;
grant execute on function public.check_observer_pin(text) to anon, authenticated;

create or replace function public.observer_pin_set()
returns boolean language sql stable security definer set search_path = public
as $$ select exists (select 1 from app_secrets where key = 'observer_pin_hash') $$;
revoke all on function public.observer_pin_set() from public;
grant execute on function public.observer_pin_set() to anon, authenticated;

create or replace function public.set_observer_pin(p text)
returns void
language plpgsql
security definer
set search_path = public, extensions
as $$
begin
  if (select public.app_role()) is distinct from 'manager' then raise exception 'not allowed'; end if;
  if p is null or char_length(p) < 6 or char_length(p) > 60 then raise exception 'invalid pin'; end if;
  insert into app_secrets values ('observer_pin_hash', crypt(p, gen_salt('bf')))
    on conflict (key) do update set value = excluded.value;
  delete from app_secrets where key in ('pin_fail_count', 'pin_locked_until');
end
$$;
revoke all on function public.set_observer_pin(text) from public, anon;
grant execute on function public.set_observer_pin(text) to authenticated;

-- المراقب يجهّز الطلب (جديد -> جاهز) بالرمز فقط، ولا يغيّر إلا الكمية المجهّزة والسعر وملاحظته
create or replace function public.prepare_order(p_pin text, p_id text, p_lines jsonb)
returns void
language plpgsql
security definer
set search_path = public, extensions
as $$
declare e jsonb; p jsonb; cur jsonb; st text; merged jsonb := '[]'::jsonb;
begin
  if not public._verify_pin(p_pin) then raise exception 'bad pin'; end if;
  if p_lines is null or jsonb_typeof(p_lines) <> 'array' then raise exception 'bad lines'; end if;
  select lines, status into cur, st from orders where id = p_id for update;
  if not found or st <> 'new' then raise exception 'order not new'; end if;
  for e in select * from jsonb_array_elements(cur) loop
    select x into p from jsonb_array_elements(p_lines) x where x->>'id' = e->>'id' limit 1;
    if p is null
       or jsonb_typeof(p->'prepQty') <> 'number' or (p->>'prepQty')::numeric < 0
       or jsonb_typeof(p->'price') <> 'number' or (p->>'price')::numeric <= 0
       or char_length(coalesce(p->>'prepNote', '')) > 500 then
      raise exception 'bad line';
    end if;
    merged := merged || jsonb_build_array(e || jsonb_build_object(
      'prepQty', p->'prepQty', 'price', p->'price', 'pricePrep', p->'price', 'prepNote', coalesce(p->>'prepNote', '')));
  end loop;
  update orders set lines = merged, status = 'ready' where id = p_id;
end
$$;
revoke all on function public.prepare_order(text, text, jsonb) from public;
grant execute on function public.prepare_order(text, text, jsonb) to anon, authenticated;
