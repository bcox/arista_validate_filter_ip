# arista_validate_filter_ip
There are times that being able to monitor a connected host and block the advertisement of that host may be desirable. Virtualized applications for example may not have the ability to hard down ports to invalidate a route.  A persistent script may be used to monitor a host and if down filter the route from the being advertised, when the host becomes available the filter is removed.

The script “validate_filter_ip.py” will ping a device once per second* and wait for three failures* before it marks the device as unavailable.  The script will then update an ip prefix-list* with the dead hosts prefix.  The user must build a policy to block routes that are added to the prefix-list from being advertised or redistributed.  An example policy is below.

\* denotes configurable


### Daemonize the script
'''
To have the system start the script automatically on startup:
daemon auto_monitor_filter_10_2_3_201
  exec /mnt/flash/validate_filter_ip.py 10.2.3.201
  no shutdown
!
'''

### BGP
We could use a policy to block outbound to peers or via the redistribution into the process.  We selected to filter the routes into the process as it should be easier to troubleshoot.

### Configuration example
'''
ip prefix-list CONNECTED_TO_BGP seq 10 permit 0.0.0.0/0 ge 24 le 32
!
route-map CONNECTED-TO-BGP deny 10
   match ip address prefix-list SCRIPTED_ROUTE_FILTER
!
route-map CONNECTED-TO-BGP permit 20
   match ip address prefix-list CONNECTED_TO_BGP
!
router bgp 65535
   redistribute connected route-map CONNECTED-TO-BGP
!
'''

Note that in the example above the SCRIPTED_ROUTE_FILTER does not exist, it will be created automatically by the script when a host is down.

### Tracing
The script is designed to be able to be ran in verbose mode (-v) and very verbose mode (-V)


### Limitations
1.	IPv4 only
2.	/31 network is hardcoded and would need to be modified for other uses
3.	Local traffic to the device will still see the route to the down host and will not be sent to alternate location(s).
4.	TTL is hard set to 1, allowing for directly connected monitoring only
