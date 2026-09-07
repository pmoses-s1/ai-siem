dataSource.name = 'Acme Edge' dst_ip = * !(net_rfc1918(dst_ip))
| group hits = count(), dst_ports = estimate_distinct(dst_port), last_seen = newest(timestamp) by src_ip, dst_ip
| filter hits >= 1
| lookup device_host = device_host, device_agentid = device_agentid, device_os = device_os, device_criticality = device_criticality from acmeEndpointByIp by device_ip = src_ip
| columns hits, dst_ports, last_seen, src_ip, dst_ip, device_agentid, device_host, device_os, device_criticality
| sort -hits
| limit 100
