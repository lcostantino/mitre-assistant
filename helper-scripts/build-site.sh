#! /bin/bash

echo "[+] Building MKDOCS Site";
mkdocs build -f ./src-mkdocs-mitre-assistant/mkdocs.yml

echo "[+] Moving Site"
rm -rf ./docs
mkdir ./docs
cp -v -R ./src-mkdocs-mitre-assistant/site/* ./docs

echo "[+] Preparing Git Commit"
DT=$(date)
git add --all;
git commit -m "push:$DT";
git push;
