dataSource.name = *
| lookup ih_excl_n = reason from ingestHealthExclusions.csv by value =:anycase dataSource.name
| lookup ih_excl_v = reason from ingestHealthExclusions.csv by value =:anycase dataSource.vendor
| filter (ih_excl_n = null and ih_excl_v = null)
| group ev = count() by source = dataSource.name, hod = simpledateformat(timestamp, 'HH', 'GMT')
| lookup exp_ev = exp_ev, sig_ev = sig_ev from ingestHealthBaseline by srckey = source
| let z = (number(ev) - number(exp_ev)) / number(sig_ev)
| filter z >= 3
| columns source, hod, ev, exp_ev, sig_ev, z
| sort -z
| limit 100
