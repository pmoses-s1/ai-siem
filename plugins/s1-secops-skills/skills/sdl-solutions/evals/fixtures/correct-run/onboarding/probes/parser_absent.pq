message = * !(parser = *) | group events = count() by dataSource.name | sort -events | limit 50
