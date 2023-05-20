#!/bin/bash

# Downloads latest copy of chisel HTTP proxy tool to current dir


arches=(
"windows_386"
"windows_amd64"
"linux_386"
"linux_amd64"
)

for arch in ${arches[@]}; do
    download_url="$(curl -s "https://api.github.com/repos/jpillora/chisel/releases/latest" \
        | jq -r ".assets[] | select(.name|endswith(\"$arch.gz\")).browser_download_url")"
    echo $download_url
    curl -Lso "chisel-$arch.gz" "$download_url"
    gunzip "chisel-$arch.gz"
done

# rename files
mv chisel-linux_386 chisel32
mv chisel-linux_amd64 chisel64
mv chisel-windows_386 chisel32.exe
mv chisel-windows_amd64 chisel64.exe

