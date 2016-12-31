#!/bin/sh

if zenity --question --text "$1" --ok-label "Allow" --cancel-label "Kill"; then
    echo '{ "decision": "allow" }'
else
    echo '{ "decision": "kill" }'
fi
