DO $bootstrap$
DECLARE
  capability_role text;
  attributes record;
  schema_created boolean := false;
  schema_oid oid;
  schema_owner_oid oid;
  migrator_oid oid;
  writer_oid oid;
  reader_oid oid;
BEGIN
  FOREACH capability_role IN ARRAY ARRAY[
    'dfe_metadata_migrator',
    'dfe_metadata_writer',
    'dfe_metadata_reader'
  ]
  LOOP
    IF NOT EXISTS (
      SELECT 1
      FROM pg_catalog.pg_roles
      WHERE rolname = capability_role
    ) THEN
      EXECUTE pg_catalog.format(
        'CREATE ROLE %I NOLOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE '
        'NOINHERIT NOREPLICATION NOBYPASSRLS',
        capability_role
      );
    END IF;

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
    WHERE rolname = capability_role;

    IF attributes.rolcanlogin
      OR attributes.rolsuper
      OR attributes.rolcreatedb
      OR attributes.rolcreaterole
      OR attributes.rolinherit
      OR attributes.rolreplication
      OR attributes.rolbypassrls
    THEN
      RAISE EXCEPTION
        'metadata capability role % has unexpected privileges or login capability',
        capability_role;
    END IF;
  END LOOP;

  IF pg_catalog.to_regnamespace('dfe_metadata') IS NULL THEN
    EXECUTE 'CREATE SCHEMA dfe_metadata AUTHORIZATION dfe_metadata_migrator';
    schema_created := true;
  END IF;

  SELECT oid INTO STRICT migrator_oid
  FROM pg_catalog.pg_roles
  WHERE rolname = 'dfe_metadata_migrator';

  SELECT oid INTO STRICT writer_oid
  FROM pg_catalog.pg_roles
  WHERE rolname = 'dfe_metadata_writer';

  SELECT oid INTO STRICT reader_oid
  FROM pg_catalog.pg_roles
  WHERE rolname = 'dfe_metadata_reader';

  IF EXISTS (
    SELECT 1
    FROM pg_catalog.pg_auth_members
    WHERE member IN (migrator_oid, writer_oid, reader_oid)
  ) THEN
    RAISE EXCEPTION
      'metadata capability roles must not be members of other roles';
  END IF;

  SELECT oid, nspowner INTO STRICT schema_oid, schema_owner_oid
  FROM pg_catalog.pg_namespace
  WHERE nspname = 'dfe_metadata';

  IF schema_owner_oid <> migrator_oid THEN
    RAISE EXCEPTION 'metadata schema dfe_metadata must be owned by dfe_metadata_migrator';
  END IF;

  IF schema_created THEN
    EXECUTE 'REVOKE ALL ON SCHEMA dfe_metadata FROM PUBLIC';
    EXECUTE 'GRANT USAGE ON SCHEMA dfe_metadata '
      'TO dfe_metadata_reader, dfe_metadata_writer';
    EXECUTE 'ALTER DEFAULT PRIVILEGES FOR ROLE dfe_metadata_migrator '
      'REVOKE ALL ON TABLES FROM PUBLIC';
    EXECUTE 'ALTER DEFAULT PRIVILEGES FOR ROLE dfe_metadata_migrator '
      'REVOKE EXECUTE ON ROUTINES FROM PUBLIC';
    EXECUTE 'ALTER DEFAULT PRIVILEGES FOR ROLE dfe_metadata_migrator '
      'IN SCHEMA dfe_metadata GRANT SELECT ON TABLES '
      'TO dfe_metadata_reader, dfe_metadata_writer';
  END IF;

  IF (
    SELECT pg_catalog.count(*)
    FROM pg_catalog.pg_namespace AS namespace
    CROSS JOIN LATERAL pg_catalog.aclexplode(
      COALESCE(
        namespace.nspacl,
        pg_catalog.acldefault('n', namespace.nspowner)
      )
    ) AS privilege
    WHERE namespace.oid = schema_oid
  ) <> 4 OR EXISTS (
    SELECT 1
    FROM pg_catalog.pg_namespace AS namespace
    CROSS JOIN LATERAL pg_catalog.aclexplode(
      COALESCE(
        namespace.nspacl,
        pg_catalog.acldefault('n', namespace.nspowner)
      )
    ) AS privilege
    WHERE namespace.oid = schema_oid
      AND NOT (
        (
          privilege.grantee = migrator_oid
          AND privilege.privilege_type IN ('CREATE', 'USAGE')
          AND NOT privilege.is_grantable
        )
        OR (
          privilege.grantee IN (reader_oid, writer_oid)
          AND privilege.privilege_type = 'USAGE'
          AND NOT privilege.is_grantable
        )
      )
  ) THEN
    RAISE EXCEPTION
      'metadata schema dfe_metadata ACL must grant only owner CREATE/USAGE and reader/writer USAGE';
  END IF;

  IF (
    SELECT pg_catalog.count(*)
    FROM pg_catalog.pg_default_acl AS defaults
    WHERE defaults.defaclrole = migrator_oid
      AND (defaults.defaclnamespace = 0 OR defaults.defaclnamespace = schema_oid)
  ) <> 2 OR EXISTS (
    SELECT 1
    FROM pg_catalog.pg_default_acl AS defaults
    WHERE defaults.defaclrole = migrator_oid
      AND (defaults.defaclnamespace = 0 OR defaults.defaclnamespace = schema_oid)
      AND NOT (
        (defaults.defaclnamespace = 0 AND defaults.defaclobjtype = 'f')
        OR (defaults.defaclnamespace = schema_oid AND defaults.defaclobjtype = 'r')
      )
  ) THEN
    RAISE EXCEPTION
      'metadata migrator default ACLs must contain only global routine and schema table policies';
  END IF;

  IF (
    SELECT pg_catalog.count(*)
    FROM pg_catalog.pg_default_acl AS defaults
    CROSS JOIN LATERAL pg_catalog.aclexplode(defaults.defaclacl) AS privilege
    WHERE defaults.defaclrole = migrator_oid
      AND defaults.defaclnamespace = 0
      AND defaults.defaclobjtype = 'f'
  ) <> 1 OR EXISTS (
    SELECT 1
    FROM pg_catalog.pg_default_acl AS defaults
    CROSS JOIN LATERAL pg_catalog.aclexplode(defaults.defaclacl) AS privilege
    WHERE defaults.defaclrole = migrator_oid
      AND defaults.defaclnamespace = 0
      AND defaults.defaclobjtype = 'f'
      AND NOT (
        privilege.grantee = migrator_oid
        AND privilege.privilege_type = 'EXECUTE'
        AND NOT privilege.is_grantable
      )
  ) THEN
    RAISE EXCEPTION
      'metadata migrator routine defaults must grant EXECUTE only to the migrator';
  END IF;

  IF (
    SELECT pg_catalog.count(*)
    FROM pg_catalog.pg_default_acl AS defaults
    CROSS JOIN LATERAL pg_catalog.aclexplode(defaults.defaclacl) AS privilege
    WHERE defaults.defaclrole = migrator_oid
      AND defaults.defaclnamespace = schema_oid
      AND defaults.defaclobjtype = 'r'
  ) <> 2 OR EXISTS (
    SELECT 1
    FROM pg_catalog.pg_default_acl AS defaults
    CROSS JOIN LATERAL pg_catalog.aclexplode(defaults.defaclacl) AS privilege
    WHERE defaults.defaclrole = migrator_oid
      AND defaults.defaclnamespace = schema_oid
      AND defaults.defaclobjtype = 'r'
      AND NOT (
        privilege.grantee IN (reader_oid, writer_oid)
        AND privilege.privilege_type = 'SELECT'
        AND NOT privilege.is_grantable
      )
  ) THEN
    RAISE EXCEPTION
      'metadata migrator table defaults must grant SELECT only to reader and writer';
  END IF;
END
$bootstrap$;
