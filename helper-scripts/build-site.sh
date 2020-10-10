#! /bin/bash

echo "[+] Building MKDOCS Site";
mkdocs build -f ./src-mkdocs-mitre-assistant/mkdocs.yml

echo "[+] Moving Site"
rm -rf ./docs/*
mv -v ./src-mkdocs-mitre-assistant/site/* ./docs

echo "[+] Preparing Git Commit"
