#!/usr/bin/env bash
# Checks .trivyignore.yaml: every entry has an id (CVE-/GHSA-), a statement (the reason: real text, at least 20
# characters, no block scalar) and an expired_at date (YYYY-MM-DD) that has not passed and is at most 180 days away.
# Only the plain layout documented in the file is accepted.
set -euo pipefail

FILE=${1:-$(dirname "$0")/../.trivyignore.yaml}
TODAY=$(date -u +%F)
LIMIT=$(date -u -d "+180 days" +%F)
fail=0
err() { echo "$FILE: $*" >&2; fail=1; }

id="" statement="" expires="" line_no=0 section=0
finish() {
  [ -z "$id" ] && return 0
  local text=${statement//[\"\']/}
  text=${text#"${text%%[![:space:]]*}"}
  if [[ $statement == '|'* || $statement == '>'* ]]; then
    err "$id: statement must be a plain one-line text, not a block scalar"
  elif [ "${#text}" -lt 20 ]; then
    err "$id: statement (the reason) is missing or shorter than 20 characters"
  fi
  if [ -z "$expires" ]; then
    err "$id: missing expired_at"
  elif ! [[ $expires =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] || ! [ "$(date -u -d "$expires" +%F 2>/dev/null)" = "$expires" ]; then
    err "$id: expired_at '$expires' is not a valid YYYY-MM-DD date"
  elif [[ ! $expires > $TODAY ]]; then
    err "$id: expired on $expires, review the finding and renew or remove the entry"
  elif [[ $expires > $LIMIT ]]; then
    err "$id: expired_at $expires is more than 180 days away (latest $LIMIT)"
  fi
  id="" statement="" expires=""
}

while IFS= read -r line || [ -n "$line" ]; do
  line=${line%$'\r'}
  line_no=$((line_no + 1))
  case $line in
    ''|'#'*) ;;
    'vulnerabilities:'*|'misconfigurations:'*|'secrets:'*|'licenses:'*)
      finish
      [[ $line =~ ^[a-z]+:(\ \[\])?$ ]] || err "line $line_no: unexpected section line"
      [[ $line == vulnerabilities:* ]] && section=1 || err "line $line_no: only the vulnerabilities section is used"
      ;;
    '  - id: '?*)
      finish
      [ "$section" -eq 1 ] || err "line $line_no: entry before the 'vulnerabilities:' line"
      id=${line#  - id: }
      [[ $id =~ ^(CVE|GHSA)-[A-Za-z0-9-]+$ ]] || err "line $line_no: id '$id' is not a CVE-/GHSA- identifier"
      ;;
    '    statement: '?*) statement=${line#    statement: } ;;
    '    statement:') statement="" ;;
    '    expired_at: '?*) expires=${line#    expired_at: } ;;
    '    '[a-z_]*:*|'      '*|'  #'*) ;;
    *) err "line $line_no: unexpected content: $line" ;;
  esac
done < "$FILE"
finish
[ "$fail" -eq 0 ] && echo "OK: $FILE"
exit $fail
