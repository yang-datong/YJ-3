#!/bin/bash

adb shell am force-stop com.xingin.xhs

adb shell am start com.xingin.xhs/.index.v2.IndexActivityV2

sleep 1

./exp.py -n 小红书
