from p4app import P4Mininet
from mininet.topo import SingleSwitchTopo
import sys
import time

N = 2

topo = SingleSwitchTopo(2)
net = P4Mininet(program='cache.p4', topo=topo)
net.start()

s1, h1, h2 = net.get('s1'), net.get('h1'), net.get('h2')



# Populate IPv4 forwarding table
table_entries = []
for i in range(1, N+1):
    table_entries.append(dict(
        table_name='MyIngress.ipv4_lpm',
        match_fields={'hdr.ipv4.dstAddr': ["10.0.0.%d" % i, 32]},
        action_name='MyIngress.ipv4_forward',
        action_params={'dstAddr': net.get('h%d'%i).intfs[0].MAC(),'port': i}
    ))

for table_entry in table_entries:
    s1.insertTableEntry(table_entry)

# Populate the cache table - only a single static value based on the spec
cache_entry = dict(
    table_name='MyIngress.static_cache',
    match_fields={'hdr.request.key': 3},
    action_name='MyIngress.retval',
    action_params={'value': 33})

s1.insertTableEntry(cache_entry)

# Now, we can test that everything works

# Start the server with some key-values
server = h1.popen('./server.py 1=11 2=22', stdout=sys.stdout, stderr=sys.stdout)
time.sleep(0.4) # wait for the server to be listenning

out = h2.cmd('./client.py 10.0.0.1 1') # expect a resp from server
assert out.strip() == "11"
out = h2.cmd('./client.py 10.0.0.1 1') # expect a value from switch cache (registers)
assert out.strip() == "11"
out = h2.cmd('./client.py 10.0.0.1 2') # resp from server
assert out.strip() == "22"
out = h2.cmd('./client.py 10.0.0.1 3') # from switch cache (table)
assert out.strip() == "33"
out = h2.cmd('./client.py 10.0.0.1 123') # resp not found from server
assert out.strip() == "NOTFOUND"

server.terminate()
