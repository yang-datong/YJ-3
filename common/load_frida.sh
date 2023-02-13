#!/bin/bash

adb_cmd(){
	adb shell "su -c '$*'"
}

file="/data/local/tmp/load_frida.sh"

adb_cmd "echo cGlkPSQocHMgLWVmIHwgZ3JlcCAtdiAiZ3JlcCJ8ICBncmVwIGZyaWRhLXNlcnZlciB8IGF3ayAne3ByaW50ICQyfScpCmlmIFsgLW4gIiRwaWQiIF07dGhlbgoJZWNobyAkcGlkO2tpbGwgJHBpZApmaQovZGF0YS9sb2NhbC90bXAvZnJpZGEtc2VydmVyICYKcGlkPSQocHMgLWVmIHwgZ3JlcCAtdiAiZ3JlcCJ8ICBncmVwIGZyaWRhLXNlcnZlciB8IGF3ayAne3ByaW50ICQyfScpCmlmIFsgLW4gIiRwaWQiIF07dGhlbiAgZWNobyAic3RhcnQgZnJpZGEgc3VjY2VzcyEhIjtleGl0OyBmaQo= | base64 -d > ${file} && chmod +x ${file} && ${file}"



