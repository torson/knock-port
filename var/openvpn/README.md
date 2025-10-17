For automating KnockPort to open the OpenVPN port, Tunnelblick supports `up <script_path>` directive .
But OpenVPN client doesn't support that, so you need to first run the script for KnockPort and then connect to OpenVPN.

File listing:
```
config-openvpn-client.linux.ovpn        # OpenVPN client config with linux LF line ending
config-openvpn-client.windows.ovpn      # OpenVPN client config with Windows CRLF line ending
config-tunnelblick.ovpn                 # Tunnelblick client config (Mac)
opevpn-client-connect.bat               # script to automate KnockPort and OpenVPN connection
```