# Wireguard Dissector for ANT+

Prerequisites:

- Install Wireshark

Install:

```sh
# Create personal plugins folder
mkdir -p ~/.local/lib/wireshark/plugins
# Symlink to there, so we can easily edit it
ln -s antplus.lua ~/.local/lib/wireshark/plugins/
```

Examples:

```sh
# Show all traffic between host and ANT transceiver
tshark -r hrm.pcapng -Y 'usb.src == "1.6.1" or usb.dst == "1.6.1"'

# Show only received packets with 15bytes of data (Transceiver version)
tshark -r hrm.pcapng -Y 'usb.src == "1.6.1" and usb.data_len == 15'
```

TODO:

- [x] Decode common messages
- [x] Validate checksum and show warning in expert dialog
- [ ] Keep track of channel device type to statefully decode broadcast messages (ANT+ data pages)
- [x] Test decoding
