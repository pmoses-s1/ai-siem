dataSource.name = 'risk' risk_object = *
| group events = count(), score = sum(number(risk_score)), tactics = estimate_distinct(mitre_tactic) by risk_object, risk_object_type
| sort -score
| limit 25
