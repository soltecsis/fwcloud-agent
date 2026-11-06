#!/bin/sh
# Called by both package formats before the service is started.
set -eu
umask 077
ROOT_DIR=${1:-/opt/fwcloud/agent}
PLACEHOLDER=REPLACE_WITH_A_UNIQUE_API_KEY_XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX
HISTORICAL_SHA256=925d0a37fc48c3dbf7a3ced5d90056bcfdf2cc9cfe9ae64a46016b6a4f384a0c
SOURCE="${ROOT_DIR}/.env"
if [ -e "${ROOT_DIR}/.env.upgrade" ] || [ -L "${ROOT_DIR}/.env.upgrade" ]; then
  SOURCE="${ROOT_DIR}/.env.upgrade"
fi
if [ -L "$SOURCE" ] || { [ -e "$SOURCE" ] && [ ! -f "$SOURCE" ]; }; then
  echo 'Invalid agent configuration file.' >&2
  exit 1
fi

# Parse data only; never execute an existing .env as shell code.
KEY=''
if [ -f "$SOURCE" ]; then
  KEY=$(awk '
    /^[[:space:]]*(export[[:space:]]+)?API_KEY[[:space:]]*=/ {
      count++; value=$0
      sub(/^[[:space:]]*(export[[:space:]]+)?API_KEY[[:space:]]*=[[:space:]]*/, "", value)
      sub(/[[:space:]]+$/, "", value)
      quote=substr(value,1,1)
      if (quote == "\"" || quote == sprintf("%c",39)) {
        value=substr(value,2); end=index(value,quote)
        tail=substr(value,end+1)
        if (!end || tail !~ /^[[:space:]]*(#.*)?$/) { invalid=1 }
        value=substr(value,1,end-1)
      } else { sub(/[[:space:]]+#.*$/, "", value) }
      if (length(value) < 16 || length(value) > 128 || value !~ /^[a-zA-Z0-9_-]+$/) { invalid=1 }
      key=value
    }
    END { if (count == 1 && !invalid) print key }
  ' "$SOURCE")
fi
ROTATE=true
if [ -n "$KEY" ] && [ "$KEY" != "$PLACEHOLDER" ]; then
  DIGEST=$(printf '%s' "$KEY" | openssl dgst -sha256 2>/dev/null) || exit 1
  DIGEST=${DIGEST##* }
  case "$DIGEST" in
    *[!a-f0-9]*|'') echo 'Cannot validate the existing credential.' >&2; exit 1 ;;
  esac
  if [ "${#DIGEST}" -ne 64 ]; then
    echo 'Cannot validate the existing credential.' >&2
    exit 1
  fi
  case "$DIGEST" in
    *"$HISTORICAL_SHA256") ;;
    *) ROTATE=false ;;
  esac
fi
if [ "$ROTATE" = false ]; then
  if [ "$SOURCE" != "${ROOT_DIR}/.env" ]; then
    mv -f "$SOURCE" "${ROOT_DIR}/.env"
  fi
  chmod 600 "${ROOT_DIR}/.env"
  exit 0
fi

KEY=$(openssl rand -hex 32 2>/dev/null) || {
  echo 'Cannot generate the agent API credential.' >&2
  exit 1
}
case "$KEY" in
  *[!a-f0-9]*|'') echo 'Invalid generated credential.' >&2; exit 1 ;;
esac
if [ "${#KEY}" -ne 64 ]; then
  echo 'Invalid generated credential.' >&2
  exit 1
fi
TEMP=$(mktemp "${ROOT_DIR}/.env.XXXXXXXX")
trap 'rm -f "$TEMP"' EXIT HUP INT TERM
if [ -f "$SOURCE" ]; then
  awk '!/^[[:space:]]*(export[[:space:]]+)?API_KEY[[:space:]]*=/' "$SOURCE" > "$TEMP"
fi
printf '\nAPI_KEY="%s"\n' "$KEY" >> "$TEMP"
chmod 600 "$TEMP"
mv -f "$TEMP" "${ROOT_DIR}/.env"
if [ "$SOURCE" != "${ROOT_DIR}/.env" ]; then
  rm -f "$SOURCE"
fi
echo 'Agent API credential regenerated; update the associated FWCloud connection.'
