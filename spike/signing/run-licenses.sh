#!/bin/sh
# Rough licence classification of every module linked into verifymain.
# Heuristic (first licence file, keyword match); verify properly before shipping.
cd "$(dirname "$0")" || exit 1
export GOWORK=off
for d in $(go list -deps -f '{{if .Module}}{{if not .Module.Main}}{{.Module.Dir}}{{end}}{{end}}' ./verifymain | sort -u); do
  f=$(ls "$d" 2>/dev/null | grep -i -E '^(licen[sc]e|copying)' | head -1)
  if [ -z "$f" ]; then echo "NOFILE $(basename "$d")"; continue; fi
  t=$(head -c 3000 "$d/$f")
  case "$t" in
    *"Apache License"*) c=Apache-2.0;;
    *"Permission is hereby granted, free of charge"*) c=MIT;;
    *"Redistribution and use in source and binary forms"*) c=BSD;;
    *"Mozilla Public License"*) c=MPL;;
    *"ISC"*) c=ISC;;
    *) c=UNKNOWN;;
  esac
  echo "$c $(basename "$d")"
done | sort | awk '{c[$1]++; if ($1=="UNKNOWN"||$1=="NOFILE"||$1=="MPL") print} END {for (k in c) print "count", k, c[k]}'
