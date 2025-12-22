#!/usr/bin/env bash
# wait-for-it.sh

set -e

hostport=(${1//:/ })
host=${hostport[0]}
port=${hostport[1]}

shift 1

while ! nc -z "$host" "$port"; do
  echo "Waiting for $host:$port..."
  sleep 1
done

echo "$host:$port is available"
exec "$@"