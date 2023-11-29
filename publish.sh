#!/usr/bin/env bash

mount ~/webdav-CERNBOX
mountpoint -q ~/webdav-CERNBOX || { echo "mount failed"; exit 1; }
rsync -ahuHAXW packages/ ~/webdav-CERNBOX/www/xrootd5alice

