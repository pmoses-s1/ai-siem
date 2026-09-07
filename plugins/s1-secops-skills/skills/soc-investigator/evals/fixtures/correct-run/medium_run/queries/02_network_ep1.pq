endpoint.name = 'CORP-WKS-0101' event.type in ('DNS Resolved', 'IP Connect')
| columns event.time, event.type, src.process.cmdline, event.dns.request, dst.ip.address, dst.port.number
| sort -event.time
| limit 100
