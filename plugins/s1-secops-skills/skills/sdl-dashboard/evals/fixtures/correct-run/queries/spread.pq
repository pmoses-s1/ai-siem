dataSource.name='alert' | group total=count(), min=min(severity_id), max=max(severity_id) by site.id | let spread = max - min, share = (total - min) / total | sort -spread | limit 25
