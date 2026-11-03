import os
import uuid

# The test runner provisions a temporary PostgreSQL container first.
os.environ["OVPN_DATABASE_URL"] = os.environ["OVPN_TEST_DATABASE_URL"]
os.environ["OVPN_DATABASE_SCHEMA"] = "api_" + uuid.uuid4().hex

# Protocol fixtures opt into unsigned XML; signing tests exercise the production default.
os.environ["OVPN_RELAY_REQUIRE_SIGNED"] = "false"
