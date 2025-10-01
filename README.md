# lab-mbp-proxy

A small useful local proxy i got claude 4.5 to make and get working in less than 2 hours.

I had a problem to solve. I access my homelab remotely via an SSH tunnel. Super easy to setup but a bit inconvienent. I would need to run ssh -D 1080 <jumphost> in a terminal, then configure my browser to use the proxy. Then all traffic would go over the proxy.

There are a few solutions to solve this (Firefox with FoxyProxy, VPNs) but i wanted something pretty much invisible on my laptop, and simple to implement in the lab.

So i thought if only i had a proxy server that i could point my browser to that would just passthru everything except my lab domain, where i'm using *.internal so it would never clash with any internet.

There are off the shelf software that can be wrenched in that direction, nothing like a tactically deployed squid proxy, but again i wanted it to be a bit more convienent than that.

So i told claude what i wanted, he cooked me up this and helped debug it too.

It runs as a launch agent, it automatically connects to the SSH tunnel on demand, it lets thru all other traffic, and also checks if i'm on the homewifi and doesn't bother connecting to the SSH tunnel. Also reads your SSH Config so you can just hardcode the host main.go and modify your config file if you need more ssh params. 

Pretty Neat.



