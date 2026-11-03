#!/bin/sh
set -eu
psql --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" --set ON_ERROR_STOP=1 <<'SQL'
\getenv app_password OPENVPN_DB_PASSWORD
\getenv policy_password RELAY_POLICY_DB_PASSWORD
CREATE ROLE openvpn LOGIN PASSWORD :'app_password' NOSUPERUSER NOCREATEDB NOCREATEROLE;
CREATE ROLE relay_policy LOGIN PASSWORD :'policy_password' NOSUPERUSER NOCREATEDB NOCREATEROLE;
ALTER ROLE relay_policy SET default_transaction_read_only = on;
REVOKE CREATE ON SCHEMA public FROM PUBLIC;
GRANT USAGE, CREATE ON SCHEMA public TO openvpn;
GRANT USAGE ON SCHEMA public TO relay_policy;
SQL
