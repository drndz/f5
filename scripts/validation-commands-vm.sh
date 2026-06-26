#!/usr/bin/env bash
# Standard Linux VM-specific remote validation commands. Java reads this file as command blocks.

##CK17 # List active systemd services
systemctl --type=service --state=active --no-pager --no-legend 2>/dev/null || true
