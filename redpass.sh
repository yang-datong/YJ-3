#!/bin/bash
adb shell am force-stop com.eagleyun.sase

adb shell am start com.eagleyun.sase/.activity.SplashActivity

sleep 1

#./exp.py -n REDpass -s model/frida_so_64.js
./exp.py -n REDpass
