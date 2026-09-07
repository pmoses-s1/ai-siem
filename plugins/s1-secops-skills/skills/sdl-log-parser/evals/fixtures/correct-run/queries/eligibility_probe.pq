dataSource.name='AcmeGateway' | columns timestamp, parser, message | sort -timestamp | limit 5
dataSource.name='AcmeGateway' | group events=count() | limit 1
dataSource.name='AcmeGateway' parser = * message = * | group events=count() by parser | sort -events | limit 20
dataSource.name='AcmeGateway' message = * !(parser = *) | group events=count() | limit 1
dataSource.name='AcmeGateway' !(message = *) !(parser = *) | group events=count() | limit 1
