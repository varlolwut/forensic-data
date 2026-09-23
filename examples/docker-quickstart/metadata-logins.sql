\getenv metadata_migrator_password DFE_METADATA_MIGRATOR_PASSWORD
\getenv metadata_writer_password DFE_METADATA_WRITER_PASSWORD
\getenv metadata_reader_password DFE_METADATA_READER_PASSWORD

SELECT pg_catalog.format(
  'CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS',
  'dfe_metadata_migrator_login'
)
WHERE NOT EXISTS (
  SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'dfe_metadata_migrator_login'
) \gexec

SELECT pg_catalog.format(
  'CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS',
  'dfe_metadata_writer_login'
)
WHERE NOT EXISTS (
  SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'dfe_metadata_writer_login'
) \gexec

SELECT pg_catalog.format(
  'CREATE ROLE %I LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOINHERIT NOREPLICATION NOBYPASSRLS',
  'dfe_metadata_reader_login'
)
WHERE NOT EXISTS (
  SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = 'dfe_metadata_reader_login'
) \gexec

DO $validation$
DECLARE
  login_role text;
  attributes record;
BEGIN
  FOREACH login_role IN ARRAY ARRAY[
    'dfe_metadata_migrator_login',
    'dfe_metadata_writer_login',
    'dfe_metadata_reader_login'
  ]
  LOOP
    SELECT
      rolcanlogin,
      rolsuper,
      rolcreatedb,
      rolcreaterole,
      rolinherit,
      rolreplication,
      rolbypassrls
    INTO STRICT attributes
    FROM pg_catalog.pg_roles
    WHERE rolname = login_role;

    IF NOT attributes.rolcanlogin
      OR attributes.rolsuper
      OR attributes.rolcreatedb
      OR attributes.rolcreaterole
      OR attributes.rolinherit
      OR attributes.rolreplication
      OR attributes.rolbypassrls
    THEN
      RAISE EXCEPTION 'metadata login role % has unexpected attributes', login_role;
    END IF;
  END LOOP;
END
$validation$;

ALTER ROLE dfe_metadata_migrator_login PASSWORD :'metadata_migrator_password';
ALTER ROLE dfe_metadata_writer_login PASSWORD :'metadata_writer_password';
ALTER ROLE dfe_metadata_reader_login PASSWORD :'metadata_reader_password';

GRANT dfe_metadata_migrator TO dfe_metadata_migrator_login;
GRANT dfe_metadata_writer TO dfe_metadata_writer_login;
GRANT dfe_metadata_reader TO dfe_metadata_writer_login;
GRANT dfe_metadata_reader TO dfe_metadata_reader_login;

ALTER ROLE dfe_metadata_reader_login SET default_transaction_read_only = on;

DO $memberships$
BEGIN
  IF EXISTS (
    WITH expected(
      capability_role,
      login_role,
      admin_option,
      inherit_option,
      set_option
    ) AS (
      VALUES
        ('dfe_metadata_migrator', 'dfe_metadata_migrator_login', false, false, true),
        ('dfe_metadata_writer', 'dfe_metadata_writer_login', false, false, true),
        ('dfe_metadata_reader', 'dfe_metadata_writer_login', false, false, true),
        ('dfe_metadata_reader', 'dfe_metadata_reader_login', false, false, true)
    ),
    actual AS (
      SELECT
        capability.rolname::text,
        login.rolname::text,
        membership.admin_option,
        membership.inherit_option,
        membership.set_option
      FROM pg_catalog.pg_auth_members AS membership
      JOIN pg_catalog.pg_roles AS capability ON capability.oid = membership.roleid
      JOIN pg_catalog.pg_roles AS login ON login.oid = membership.member
      WHERE capability.rolname IN (
        'dfe_metadata_migrator',
        'dfe_metadata_writer',
        'dfe_metadata_reader'
      ) OR login.rolname IN (
        'dfe_metadata_migrator_login',
        'dfe_metadata_writer_login',
        'dfe_metadata_reader_login'
      )
    )
    (
      SELECT * FROM actual
      EXCEPT
      SELECT * FROM expected
    )
    UNION ALL
    (
      SELECT * FROM expected
      EXCEPT
      SELECT * FROM actual
    )
  ) THEN
    RAISE EXCEPTION 'metadata login membership graph or options are unexpected';
  END IF;
END
$memberships$;

REVOKE ALL ON DATABASE dfe_metadata FROM PUBLIC;
REVOKE ALL ON DATABASE dfe_metadata FROM
  dfe_metadata_migrator_login,
  dfe_metadata_writer_login,
  dfe_metadata_reader_login;
GRANT CONNECT ON DATABASE dfe_metadata
TO dfe_metadata_migrator_login, dfe_metadata_writer_login, dfe_metadata_reader_login;

DO $database_acl$
DECLARE
  database_owner oid;
BEGIN
  SELECT datdba INTO STRICT database_owner
  FROM pg_catalog.pg_database
  WHERE datname = 'dfe_metadata';

  IF pg_catalog.pg_get_userbyid(database_owner) <> 'postgres' THEN
    RAISE EXCEPTION 'metadata database must be owned by postgres';
  END IF;

  IF (
    SELECT pg_catalog.count(*)
    FROM pg_catalog.pg_database AS database
    CROSS JOIN LATERAL pg_catalog.aclexplode(
      COALESCE(database.datacl, pg_catalog.acldefault('d', database.datdba))
    ) AS privilege
    WHERE database.datname = 'dfe_metadata'
  ) <> 6 OR EXISTS (
    SELECT 1
    FROM pg_catalog.pg_database AS database
    CROSS JOIN LATERAL pg_catalog.aclexplode(
      COALESCE(database.datacl, pg_catalog.acldefault('d', database.datdba))
    ) AS privilege
    WHERE database.datname = 'dfe_metadata'
      AND NOT (
        (
          privilege.grantee = database_owner
          AND privilege.privilege_type IN ('CONNECT', 'CREATE', 'TEMPORARY')
          AND NOT privilege.is_grantable
        ) OR (
          privilege.grantee IN (
            SELECT oid
            FROM pg_catalog.pg_roles
            WHERE rolname IN (
              'dfe_metadata_migrator_login',
              'dfe_metadata_writer_login',
              'dfe_metadata_reader_login'
            )
          )
          AND privilege.privilege_type = 'CONNECT'
          AND NOT privilege.is_grantable
        )
      )
  ) THEN
    RAISE EXCEPTION 'metadata database ACL is unexpected';
  END IF;
END
$database_acl$;
