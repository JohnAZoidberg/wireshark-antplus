#!/usr/bin/env bash
set -euo pipefail

# Can parse Startup Notification Message
tshark -r hrm2.pcapng -Y 'usb.src == "1.6.1" and ant.msg_id == 0x6f' -O antplus \
  | grep StartupNotificationMessage

# Properly parses ANT Version string
tshark -r hrm2.pcapng -Y 'usb.src == "1.6.1" and ant.msg_id == 0x3e' -O antplus \
  | grep "ANT Version: AP2USB1.05$"

# Properly decodes and calculates messaging period
tshark -r hrm2.pcapng -Y 'usb.dst == "1.6.1" and ant.msg_id == 0x43' -O antplus \
  | grep "Messaging Period: 8070 (4.060 Hz)$"
