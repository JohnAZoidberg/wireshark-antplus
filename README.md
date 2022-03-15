# Wireshark Dissector for ANT+

Can be used to capture traffic between an application, such as
[j-antplus](https://github.com/JohnAZoidberg/j-antplus) or
[SensorWrangler](https://github.com/JohnAZoidberg/SensorWrangler) and an ANT+
USB transceiver.


Prerequisites:

- Install Wireshark
- For capturing USB traffic load kernel module: `sudo modprobe usbmon`

Install:

```sh
# Create personal plugins folder
mkdir -p ~/.local/lib/wireshark/plugins
# Symlink to there, so we can easily edit it
ln -s antplus.lua ~/.local/lib/wireshark/plugins/
```

Examples (based on example capture):

```sh
# Find USB bus and device number of transceiver.
# In this case Bus 1 and Device 6. Endpoint is probably always 1.
# So you need to filter by: usb.src == "1.6.1" or usb.dst == "1.6.1"
> lsusb
Bus 004 Device 001: ID 1d6b:0003 Linux Foundation 3.0 root hub
Bus 002 Device 002: ID 0bda:0316 Realtek Semiconductor Corp. Card Reader
Bus 001 Device 002: ID 8087:0a2b Intel Corp. Bluetooth wireless interface
Bus 001 Device 006: ID 0fcf:1008 Dynastream Innovations, Inc. ANTUSB2 Stick
Bus 001 Device 001: ID 1d6b:0002 Linux Foundation 2.0 root hub

# Make sure to adjust 1.6 to your bus and device number
# Show all traffic between host and ANT transceiver
> tshark -r hrm.pcapng -Y 'usb.src == "1.6.1" or usb.dst == "1.6.1"'

# Show only received packets with 15bytes of data (Transceiver version)
> tshark -r hrm.pcapng -Y 'usb.src == "1.6.1" and usb.data_len == 15'
```

TODO:

- [x] Decode common messages
- [x] Validate checksum and show warning in expert dialog
- [ ] Keep track of channel device type to statefully decode broadcast messages (ANT+ data pages)
- [x] Test decoding
