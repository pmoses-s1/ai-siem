dataSource.name = 'Akamai' dns_rcode != 'NOERROR' client_ip = *
| lookup excl_asset = reason from akaExclScanners.csv by cidr =:cidr client_ip
| filter excl_asset = null
| lookup excl_domain = reason from akaExclDomains.csv by value =:anycase query_domain
| filter excl_domain = null
| group failures = count(), domains = estimate_distinct(query_domain) by client_ip, query_domain
| filter failures >= 25
| columns failures, domains, client_ip, query_domain
| sort -failures
| limit 200
