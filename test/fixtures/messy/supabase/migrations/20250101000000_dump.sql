--
-- PostgreSQL database dump. Its session settings must end with this file.
--
SET statement_timeout = 0;
SELECT pg_catalog.set_config('search_path', '', false);
SET check_function_bodies = false;
SET row_security = off;

-- ---------------------------------------------------------------------------
-- Note 0: the kind of long header pg_dump and AI builders write.
-- Note 1: the kind of long header pg_dump and AI builders write.
-- Note 2: the kind of long header pg_dump and AI builders write.
-- Note 3: the kind of long header pg_dump and AI builders write.
-- Note 4: the kind of long header pg_dump and AI builders write.
-- Note 5: the kind of long header pg_dump and AI builders write.
-- Note 6: the kind of long header pg_dump and AI builders write.
-- Note 7: the kind of long header pg_dump and AI builders write.
-- Note 8: the kind of long header pg_dump and AI builders write.
-- Note 9: the kind of long header pg_dump and AI builders write.
-- Note 10: the kind of long header pg_dump and AI builders write.
-- Note 11: the kind of long header pg_dump and AI builders write.
-- Note 12: the kind of long header pg_dump and AI builders write.
-- Note 13: the kind of long header pg_dump and AI builders write.
-- Note 14: the kind of long header pg_dump and AI builders write.
-- Note 15: the kind of long header pg_dump and AI builders write.
-- Note 16: the kind of long header pg_dump and AI builders write.
-- Note 17: the kind of long header pg_dump and AI builders write.
-- Note 18: the kind of long header pg_dump and AI builders write.
-- Note 19: the kind of long header pg_dump and AI builders write.
-- Note 20: the kind of long header pg_dump and AI builders write.
-- Note 21: the kind of long header pg_dump and AI builders write.
-- Note 22: the kind of long header pg_dump and AI builders write.
-- Note 23: the kind of long header pg_dump and AI builders write.
-- Note 24: the kind of long header pg_dump and AI builders write.
-- Note 25: the kind of long header pg_dump and AI builders write.
-- Note 26: the kind of long header pg_dump and AI builders write.
-- Note 27: the kind of long header pg_dump and AI builders write.
-- Note 28: the kind of long header pg_dump and AI builders write.
-- Note 29: the kind of long header pg_dump and AI builders write.
-- Note 30: the kind of long header pg_dump and AI builders write.
-- Note 31: the kind of long header pg_dump and AI builders write.
-- Note 32: the kind of long header pg_dump and AI builders write.
-- Note 33: the kind of long header pg_dump and AI builders write.
-- Note 34: the kind of long header pg_dump and AI builders write.
-- Note 35: the kind of long header pg_dump and AI builders write.
-- Note 36: the kind of long header pg_dump and AI builders write.
-- Note 37: the kind of long header pg_dump and AI builders write.
-- Note 38: the kind of long header pg_dump and AI builders write.
-- Note 39: the kind of long header pg_dump and AI builders write.
-- ---------------------------------------------------------------------------

CREATE TYPE "public"."app_role" AS ENUM ('admin', 'manager', 'finance');

CREATE TABLE "public"."user_roles" (
    "id" "uuid" DEFAULT "extensions"."uuid_generate_v4"() NOT NULL PRIMARY KEY,
    "user_id" "uuid" NOT NULL REFERENCES "auth"."users"("id"),
    "role" "public"."app_role" NOT NULL
);
ALTER TABLE "public"."user_roles" ENABLE ROW LEVEL SECURITY;
CREATE POLICY "own roles" ON "public"."user_roles" FOR SELECT TO "authenticated" USING ("user_id" = "auth"."uid"());

CREATE FUNCTION "public"."is_staff"("uid" "uuid") RETURNS boolean
    LANGUAGE "sql" STABLE SECURITY DEFINER SET "search_path" = ''
    AS $$ SELECT EXISTS (SELECT 1 FROM public.user_roles WHERE user_id = uid) $$;
REVOKE EXECUTE ON FUNCTION "public"."is_staff"("uuid") FROM "anon";

-- Any row in user_roles makes someone staff: B must not get one from the seed.
CREATE TABLE "public"."invoices" (
    "id" "uuid" DEFAULT "extensions"."uuid_generate_v4"() NOT NULL PRIMARY KEY,
    "user_id" "uuid" NOT NULL REFERENCES "auth"."users"("id"),
    "amount" numeric(4,2) NOT NULL
);
ALTER TABLE "public"."invoices" ENABLE ROW LEVEL SECURITY;
CREATE POLICY "own or staff" ON "public"."invoices" FOR ALL TO "authenticated"
    USING ("user_id" = "auth"."uid"() OR "public"."is_staff"("auth"."uid"()))
    WITH CHECK ("user_id" = "auth"."uid"());
