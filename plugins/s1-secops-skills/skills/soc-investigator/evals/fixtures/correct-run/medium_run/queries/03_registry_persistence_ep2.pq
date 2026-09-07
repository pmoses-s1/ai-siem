endpoint.name = 'CORP-WKS-0207' event.type = 'Registry Value Create'
| filter registry.keyPath contains:anycase("\\CurrentVersion\\Run")
| columns event.time, registry.keyPath, registry.value, src.process.cmdline
| sort -event.time
| limit 100
