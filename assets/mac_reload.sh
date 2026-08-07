#/bin/bash

sudo launchctl disable system/com.dns-relay
sudo launchctl bootout system/com.dns-relay

sudo launchctl bootstrap system /Library/LaunchDaemons/com.dns-relay.plist
sudo launchctl enable system/com.dns-relay
sudo launchctl kickstart -k system/com.dns-relay
