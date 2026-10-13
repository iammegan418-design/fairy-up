-- =====================================================================
-- 仙女飛升計畫｜Supabase 設定 SQL（測試版 fairy-up-test 用）
-- 在 Supabase → SQL Editor 執行。分三段，請依序執行。
-- =====================================================================


-- ===== 第 1 段：檢查現況（只讀，不會改任何東西）=====================
-- 執行後把結果截圖或複製給 Claude，確認目前結構。

select table_name, column_name, data_type, is_nullable, column_default
from information_schema.columns
where table_schema = 'public' and table_name in ('fairy_members','fairy_classes')
order by table_name, ordinal_position;

select tablename, rowsecurity as rls_enabled
from pg_tables
where schemaname = 'public' and tablename in ('fairy_members','fairy_classes');

select tablename, policyname, cmd, roles, qual, with_check
from pg_policies
where schemaname = 'public' and tablename in ('fairy_members','fairy_classes');


-- ===== 第 2 段：建立正確的資料表、權限與打卡函式 =====================
-- 安全機制：如果兩個資料表裡已經有資料，這段會自動停止，不會刪掉任何東西。
-- 資料表是空的（剛建立）才會重建成新版需要的結構。

do $$
declare n int;
begin
  if to_regclass('public.fairy_members') is not null then
    execute 'select count(*) from public.fairy_members' into n;
    if n > 0 then raise exception 'fairy_members 已有 % 筆資料，為避免覆蓋已停止。請把第 1 段結果傳給 Claude。', n; end if;
  end if;
  if to_regclass('public.fairy_classes') is not null then
    execute 'select count(*) from public.fairy_classes' into n;
    if n > 0 then raise exception 'fairy_classes 已有 % 筆資料，為避免覆蓋已停止。請把第 1 段結果傳給 Claude。', n; end if;
  end if;
end $$;

drop table if exists public.fairy_members cascade;
drop table if exists public.fairy_classes cascade;

-- 班級
create table public.fairy_classes (
  id          uuid primary key default gen_random_uuid(),
  name        text not null check (char_length(name) between 1 and 30),
  start_date  date not null,
  end_date    date not null,
  is_current  boolean not null default false,
  created_at  timestamptz not null default now(),
  check (end_date >= start_date)
);
-- 同一時間只能有一個「目前班級」
create unique index fairy_classes_one_current on public.fairy_classes (is_current) where is_current;

-- 班級成員（每人每班一筆，打卡紀錄存在 logs）
create table public.fairy_members (
  id          uuid primary key default gen_random_uuid(),
  class_id    uuid not null references public.fairy_classes(id) on delete cascade,
  user_id     uuid not null default auth.uid() references auth.users(id) on delete cascade,
  name        text not null check (char_length(name) between 1 and 30),
  upline      text not null default '' check (char_length(upline) <= 30),
  mode        smallint not null default 1 check (mode between 1 and 3),
  base        integer not null default 0 check (base >= 0),
  logs        jsonb not null default '{}'::jsonb,
  created_at  timestamptz not null default now(),
  updated_at  timestamptz not null default now(),
  unique (class_id, user_id)
);
create index fairy_members_class_idx on public.fairy_members (class_id);
create index fairy_members_user_idx  on public.fairy_members (user_id);

-- 團隊長名單
create table if not exists public.fairy_admins (
  user_id     uuid primary key references auth.users(id) on delete cascade,
  created_at  timestamptz not null default now()
);

-- 判斷目前登入者是不是團隊長
create or replace function public.is_fairy_admin()
returns boolean language sql stable security definer set search_path = public as $$
  select exists (select 1 from public.fairy_admins where user_id = auth.uid());
$$;
revoke all on function public.is_fairy_admin() from public, anon;
grant execute on function public.is_fairy_admin() to authenticated;

-- 開啟 RLS（列層級權限）
alter table public.fairy_classes enable row level security;
alter table public.fairy_members enable row level security;
alter table public.fairy_admins  enable row level security;

-- 未登入的人什麼都碰不到
revoke all on public.fairy_classes, public.fairy_members, public.fairy_admins from anon;
grant select, insert, update, delete on public.fairy_classes, public.fairy_members to authenticated;
grant select on public.fairy_admins to authenticated;

-- 班級：登入者可看；只有團隊長能新增、修改、刪除
create policy classes_read   on public.fairy_classes for select to authenticated using (true);
create policy classes_insert on public.fairy_classes for insert to authenticated with check (public.is_fairy_admin());
create policy classes_update on public.fairy_classes for update to authenticated using (public.is_fairy_admin()) with check (public.is_fairy_admin());
create policy classes_delete on public.fairy_classes for delete to authenticated using (public.is_fairy_admin());

-- 成員：登入者可看全班進度（班級總覽、全班曲線需要）
create policy members_read on public.fairy_members for select to authenticated using (true);
-- 只能把「自己」加入「目前班級」
create policy members_insert_self on public.fairy_members for insert to authenticated
  with check (
    user_id = (select auth.uid())
    and exists (select 1 from public.fairy_classes c where c.id = class_id and c.is_current)
  );
-- 只能改自己的紀錄；團隊長可以改全部
create policy members_update on public.fairy_members for update to authenticated
  using      (user_id = (select auth.uid()) or public.is_fairy_admin())
  with check (user_id = (select auth.uid()) or public.is_fairy_admin());
-- 只有團隊長能移除成員
create policy members_delete on public.fairy_members for delete to authenticated
  using (public.is_fairy_admin());

-- 團隊長名單：每個人只看得到自己在不在名單上；沒有任何人能從網頁寫入
drop policy if exists admins_read_self on public.fairy_admins;
create policy admins_read_self on public.fairy_admins for select to authenticated
  using (user_id = (select auth.uid()));

-- 打卡函式：只合併當天那一筆，不會覆蓋其他天（換手機同時打卡也安全）
-- security invoker = 照樣受上面的 RLS 限制，改不了別人的資料
create or replace function public.fairy_checkin(p_member uuid, p_day date, p_entry jsonb)
returns void language plpgsql security invoker set search_path = public as $$
begin
  update public.fairy_members
     set logs = coalesce(logs, '{}'::jsonb) || jsonb_build_object(p_day::text, p_entry),
         updated_at = now()
   where id = p_member;
  if not found then
    raise exception '沒有權限或找不到成員' using errcode = '42501';
  end if;
end $$;
revoke all on function public.fairy_checkin(uuid, date, jsonb) from public, anon;
grant execute on function public.fairy_checkin(uuid, date, jsonb) to authenticated;

-- 即時同步（別人打卡時畫面自動更新）
do $$
begin
  if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and tablename = 'fairy_members') then
    alter publication supabase_realtime add table public.fairy_members;
  end if;
  if not exists (select 1 from pg_publication_tables where pubname = 'supabase_realtime' and tablename = 'fairy_classes') then
    alter publication supabase_realtime add table public.fairy_classes;
  end if;
end $$;


-- ===== 第 3 段：把自己設為團隊長 =====================================
-- 先到測試版網頁「註冊帳號」，再回來執行這段（把 Email 換成妳註冊用的）。

insert into public.fairy_admins (user_id)
select id from auth.users where email = 'iammegan418@gmail.com'
on conflict do nothing;

-- 確認：應該會列出妳的 Email
select u.email from public.fairy_admins a join auth.users u on u.id = a.user_id;
