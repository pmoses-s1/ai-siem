event.type = 'Process Creation' endpoint.name = 'CORP-WKS-0101'
| columns event.time, src.process.pid, src.process.cmdline, src.process.user, src.process.parent.cmdline
| sort -event.time
| limit 100
