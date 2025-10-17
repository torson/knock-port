@echo off

echo Running pre-connection script...
set SERVER_IP=1.2.3.4
echo Sending HTTP request
curl -m 1 -d "app=test_service_local&access_key=test_secret_http" http://%SERVER_IP%/step-1
echo Sending HTTPS request
curl -m 1 -d "app=test_service_local&access_key=test_secret_http" -k https://%SERVER_IP%/step-2

echo Starting OpenVPN...
start "" "C:\Program Files\OpenVPN\bin\openvpn-gui.exe" --connect config-openvpn-client.windows.ovpn
