+++
date = '2026-04-20'
draft = false
title = 'Pico North-South writeup'
ShowToc = true
tags = ["picoCTF", "web"]
+++

## Overview

I've set up geo-based routing - can you outsmart it? You're trying to retrieve the flag, but there's a catch: access to the real service is restricted based on your geographic location. Only requests from a specific region are routed to the server that holds the flag. Everyone else is sent somewhere... less interesting.

## Identifying the vulnerabilities

We also receive the nginx conf file; It's serving two proxies, and one is only available to people with `$geoip2_data_country_code = IS`. That's Iceland, upon looking at countrycode.org.

So, we need to use a VPN, specifically from Iceland. I have a paid VPN which has a lot of locations, including Iceland. 

![challenge-screenshot](flag1.png#center)

I also watched a [writeup](https://www.youtube.com/watch?v=IU8Zg2c560k&list=PLHNW1N94IxtLUpOus6mvGaHDAwjmqMBvg&index=2), with a free way to do it instead, because I was curious about it. He suggests using tor, with choosing the location of his exit node to be iceland. 

I didn't have tor installed, so I installed it now, and now I can run the app with `tor-vpn`. But, to use our own conf files, we need to run the binary using `tor -f /path/conf` (in this case, the conf file's contents being `ExitNodes {is} \ StrictNodes 1`).

You can check your connection via `curl --socks5-hostname 127.0.0.1:9050 https://check.torproject.org/api/ip`; 

To connect anywhere with that tor instance just use `curl --socks5-hostname 127.0.0.1:9050 http://website/`. Using that to connect to pico, we see the flag!

![challenge-screenshot](flag.png#center)





