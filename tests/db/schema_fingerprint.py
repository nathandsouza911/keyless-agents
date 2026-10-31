"""Fingerprint of the security-relevant database state as PostgreSQL holds it
(fifth review I-2, targeted review I-c, final review L-1).

Compares definitions, not counts. Covered, each as rows compared whole:
constraint, trigger, index, rule and policy definitions; every function in
schema public (body, STRICT, volatility, security definer, settings, return
type, owner and EXECUTE privileges); columns (type, NOT NULL, default,
identity, generated, collation, column privileges); every relation in public
(kind, owner, privileges, row security); schema and database ownership and
privileges; database- and role-level settings that reach this database;
extensions, event triggers, default privileges, and the attributes and
memberships of the clw roles.

A NULL privilege list (the built-in default) is shown as '<default>', so it
never compares equal to an explicit list. Not covered: other databases, the
server configuration file, and pg_catalog itself.
"""

from __future__ import annotations

_QUERIES = {
    "constraints": """
        SELECT conname, pg_get_constraintdef(oid, true), convalidated, condeferrable
          FROM pg_constraint WHERE conrelid = 'public.audit_events'::regclass ORDER BY conname""",
    "triggers": """
        SELECT tgname, pg_get_triggerdef(oid, true), tgenabled::text
          FROM pg_trigger WHERE tgrelid = 'public.audit_events'::regclass AND NOT tgisinternal ORDER BY tgname""",
    "functions": """
        SELECT p.proname, pg_get_function_identity_arguments(p.oid), md5(p.prosrc), p.provolatile::text,
               p.prosecdef, p.proisstrict, p.proleakproof, p.proparallel::text, p.prokind::text,
               p.prorettype::regtype::text, coalesce(array_to_string(p.proconfig, ','), ''),
               p.proowner::regrole::text, coalesce(p.proacl::text, '<default>')
          FROM pg_proc p WHERE p.pronamespace = 'public'::regnamespace ORDER BY 1, 2""",
    "columns": """
        SELECT a.attname, format_type(a.atttypid, a.atttypmod), a.attnotnull, a.attisdropped,
               coalesce(pg_get_expr(d.adbin, d.adrelid), ''), a.attidentity::text, a.attgenerated::text,
               a.attcollation::regcollation::text, coalesce(a.attacl::text, '<default>')
          FROM pg_attribute a LEFT JOIN pg_attrdef d ON d.adrelid = a.attrelid AND d.adnum = a.attnum
         WHERE a.attrelid = 'public.audit_events'::regclass AND a.attnum > 0 ORDER BY a.attnum""",
    "relations": """
        SELECT c.relname, c.relkind::text, c.relowner::regrole::text, coalesce(c.relacl::text, '<default>'),
               c.relrowsecurity, c.relforcerowsecurity, c.relpersistence::text
          FROM pg_class c WHERE c.relnamespace = 'public'::regnamespace ORDER BY 1""",
    "indexes": """
        SELECT i.indexrelid::regclass::text, pg_get_indexdef(i.indexrelid), i.indisvalid, i.indisready,
               i.indislive
          FROM pg_index i JOIN pg_class c ON c.oid = i.indrelid
         WHERE c.relnamespace = 'public'::regnamespace ORDER BY 1""",
    "rules": """
        SELECT c.relname, r.rulename, pg_get_ruledef(r.oid, true), r.ev_enabled::text
          FROM pg_rewrite r JOIN pg_class c ON c.oid = r.ev_class
         WHERE c.relnamespace = 'public'::regnamespace ORDER BY 1, 2""",
    "policies": """
        SELECT c.relname, p.polname, p.polcmd::text, p.polpermissive,
               coalesce(pg_get_expr(p.polqual, p.polrelid), ''),
               coalesce(pg_get_expr(p.polwithcheck, p.polrelid), ''),
               ARRAY(SELECT r::regrole::text FROM unnest(p.polroles) r ORDER BY 1)::text
          FROM pg_policy p JOIN pg_class c ON c.oid = p.polrelid
         WHERE c.relnamespace = 'public'::regnamespace ORDER BY 1, 2""",
    "schemas": """
        SELECT nspname, nspowner::regrole::text, coalesce(nspacl::text, '<default>')
          FROM pg_namespace WHERE nspname NOT LIKE 'pg!_%' ESCAPE '!' AND nspname <> 'information_schema'
         ORDER BY 1""",
    "database": """
        SELECT datdba::regrole::text, coalesce(datacl::text, '<default>'), datallowconn, datconnlimit
          FROM pg_database WHERE datname = current_database()""",
    "settings": """
        SELECT CASE WHEN s.setdatabase = 0 THEN '<all databases>' ELSE '<this database>' END,
               CASE WHEN s.setrole = 0 THEN '<all roles>' ELSE s.setrole::regrole::text END,
               coalesce(array_to_string(s.setconfig, ','), '')
          FROM pg_db_role_setting s
         WHERE s.setdatabase = 0
            OR s.setdatabase = (SELECT oid FROM pg_database WHERE datname = current_database())
         ORDER BY 1, 2, 3""",
    "extensions": """
        SELECT extname, extversion, extnamespace::regnamespace::text FROM pg_extension ORDER BY 1""",
    "event_triggers": """
        SELECT evtname, evtevent, evtenabled::text, evtfoid::regproc::text FROM pg_event_trigger ORDER BY 1""",
    "default_privileges": """
        SELECT defaclrole::regrole::text, defaclnamespace::regnamespace::text, defaclobjtype::text,
               defaclacl::text
          FROM pg_default_acl ORDER BY 1, 2, 3""",
    "roles": """
        SELECT r.rolname, r.rolsuper, r.rolinherit, r.rolcreaterole, r.rolcreatedb, r.rolcanlogin,
               r.rolreplication, r.rolbypassrls,
               ARRAY(SELECT m.roleid::regrole::text FROM pg_auth_members m WHERE m.member = r.oid ORDER BY 1)::text
          FROM pg_roles r WHERE r.rolname LIKE 'clw%' ORDER BY 1""",
}


async def schema_fingerprint(conn) -> dict[str, tuple]:
    return {name: tuple(tuple(row) for row in await conn.fetch(sql)) for name, sql in _QUERIES.items()}


def schema_differences(reference: dict[str, tuple], current: dict[str, tuple]) -> list[str]:
    out = []
    for name in _QUERIES:
        before, after = set(reference.get(name, ())), set(current.get(name, ()))
        for row in sorted(before - after, key=repr):
            out.append(f"{name}: missing or changed {row}")
        for row in sorted(after - before, key=repr):
            out.append(f"{name}: new or changed {row}")
    return out


def production_shaped(fingerprint: dict[str, tuple]) -> list[str]:
    """Problems that are never acceptable, whatever the reference."""
    problems = [f"constraint not validated: {r[0]}" for r in fingerprint["constraints"] if not r[2]]
    problems += [f"trigger not enabled for ordinary sessions: {r[0]} ({r[2]})" for r in fingerprint["triggers"]
                 if r[2] != "O"]
    problems += [f"database- or role-level setting: {r}" for r in fingerprint["settings"]]
    problems += [f"rule on {r[0]}: {r[1]}" for r in fingerprint["rules"]]
    problems += [f"index not usable: {r[0]}" for r in fingerprint["indexes"] if not (r[2] and r[3] and r[4])]
    return problems
