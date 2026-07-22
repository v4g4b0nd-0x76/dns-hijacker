#/bin/bash

sudo launchctl disable system/com.dns-hijacker
sudo launchctl bootout system/com.dns-hijacker

sudo launchctl bootstrap system /Library/LaunchDaemons/com.dns-hijacker.plist
sudo launchctl enable system/com.dns-hijacker
sudo launchctl kickstart -k system/com.dns-hijacker
