#!/bin/sh
# Start the public demo from the seeded copy, so every start (and every wake-up
# after the container sleeps) shows the same fresh sample data.
set -eu
mkdir -p /tmp/kavlotryx
cp /opt/kavlotryx/demo.db /tmp/kavlotryx/demo.db
cp /opt/kavlotryx/tracker.json /tmp/kavlotryx/tracker.json
exec kavlo serve --host 0.0.0.0 --port "${PORT:-8080}"
