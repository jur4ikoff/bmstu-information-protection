#!/usr/bin/env bash
# Demonstrates a one-pair known-plaintext attack against the lab Enigma model.
set -euo pipefail

project_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
work_dir=$(mktemp -d "${TMPDIR:-/tmp}/enigma-attack.XXXXXX")
trap 'rm -rf "$work_dir"' EXIT

if ! command -v zip >/dev/null 2>&1; then
  echo "Ошибка: для демонстрации требуется утилита zip." >&2
  exit 1
fi

mkdir -p "$work_dir/plain"
printf '%s\n' \
  'Known plaintext for Enigma laboratory attack.' \
  'The archive header and this reference archive are available to the attacker.' \
  'Only one plugboard pair is unknown: 65:66.' > "$work_dir/plain/report.txt"
(cd "$work_dir/plain" && zip -q "$work_dir/source.zip" report.txt)

# In an actual known-plaintext attack this is a known fragment of an archive
# of the same format. Here it is deliberately taken from the reference ZIP.
known_hex=$(od -An -tx1 -N128 "$work_dir/source.zip" | tr -d ' \n')

export GOCACHE="${GOCACHE:-$work_dir/go-cache}"
cd "$project_dir"

go run ./cmd/enigma -e \
  --input "$work_dir/source.zip" \
  --output "$work_dir/cipher.egar" \
  --rotors IV,II,I,III --reflector B --positions 7,12,34,56 \
  --plugboard 65:66

result=$(go run ./cmd/enigma attack \
  --input "$work_dir/cipher.egar" \
  --rotors IV,II,I,III --reflector B --positions 7,12,34,56 \
  --known-hex "$known_hex")

expected='candidate plugboard pair: 65:66'
if ! grep -Fqx "$expected" <<< "$result"; then
	echo 'Демонстрация не прошла: среди кандидатов нет пары 65:66.' >&2
	exit 1
fi
candidate_count=$(grep -c '^candidate plugboard pair:' <<< "$result")
printf 'Найдена искомая пара: 65:66 (кандидатов после фильтрации: %s).\n' "$candidate_count"
echo 'Успех: известный фрагмент сузил поиск и восстановил часть настройки панели.'
