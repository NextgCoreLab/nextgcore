#!/bin/bash
# update-api-docs.sh — Generates api-index.json from OpenAPI specs in docs/openapi/
# Usage: cd nextgcore && bash docs/scripts/update-api-docs.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
DOCS_DIR="$(dirname "$SCRIPT_DIR")"
OPENAPI_DIR="$DOCS_DIR/openapi"
OUTPUT="$DOCS_DIR/api-index.json"

if [ ! -d "$OPENAPI_DIR" ]; then
  echo "Error: $OPENAPI_DIR not found"
  exit 1
fi

echo "Scanning $OPENAPI_DIR for OpenAPI specs..."

# Build JSON array
echo "[" > "$OUTPUT"

first=true
for spec in "$OPENAPI_DIR"/*.yaml "$OPENAPI_DIR"/*.json; do
  [ -f "$spec" ] || continue

  filename=$(basename "$spec")
  relpath="openapi/$filename"

  # Extract title from info.title field
  title=$(grep -m1 '^\s*title:' "$spec" 2>/dev/null | sed 's/^[[:space:]]*title:[[:space:]]*//' | sed 's/^["'\'']//' | sed 's/["'\'']*$//' | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//')

  # Fallback: derive name from filename
  if [ -z "$title" ]; then
    title=$(echo "$filename" | sed 's/\.yaml$//' | sed 's/\.json$//' | sed 's/_/ /g' | sed 's/-/ /g')
  fi

  # Extract description
  desc=$(grep -m1 '^\s*description:' "$spec" 2>/dev/null | sed 's/^[[:space:]]*description:[[:space:]]*//' | sed 's/^["'\'']//' | sed 's/["'\'']*$//' | sed 's/^[[:space:]]*//' | sed 's/[[:space:]]*$//' | head -c 120)

  if [ "$first" = true ]; then
    first=false
  else
    echo "," >> "$OUTPUT"
  fi

  # Escape any quotes in title/desc for valid JSON
  title=$(echo "$title" | sed 's/"/\\"/g')
  desc=$(echo "$desc" | sed 's/"/\\"/g')

  printf '  {"name": "%s", "file": "%s", "description": "%s"}' "$title" "$relpath" "$desc" >> "$OUTPUT"

  echo "  Found: $title ($relpath)"
done

echo "" >> "$OUTPUT"
echo "]" >> "$OUTPUT"

count=$(grep -c '"file"' "$OUTPUT")
echo ""
echo "Generated $OUTPUT with $count specs."
