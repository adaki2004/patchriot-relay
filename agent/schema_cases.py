"""Generate bounded schema cases offline. All target I/O belongs to the broker."""
import json
from pathlib import Path
import sys
from urllib.parse import urlencode


def check_references(value, depth=0):
    if depth > 32:
        raise ValueError('schema_depth_limit')
    if isinstance(value, dict):
        if '$ref' in value and not str(value['$ref']).startswith('#/'):
            raise ValueError('external_schema_reference')
        for child in value.values():
            check_references(child, depth + 1)
    elif isinstance(value, list):
        for child in value:
            check_references(child, depth + 1)


def generate(document, origin):
    import schemathesis
    from hypothesis import given, settings, Phase, HealthCheck
    from hypothesis.errors import Unsatisfiable
    if schemathesis.__version__ != '4.33.1':
        raise ValueError('schema_version_mismatch')
    if not isinstance(document, dict):
        raise ValueError('schema_object_required')
    check_references(document)
    graphql_mode = '__schema' in document or '__schema' in document.get('data', {})
    schema = (schemathesis.graphql.from_dict(document, config=schemathesis.Config()) if graphql_mode
              else schemathesis.openapi.from_dict(document, config=schemathesis.Config()))
    cases, gaps = [], []
    for result in schema.get_all_operations():
        if len(cases) >= 12:
            gaps.append('schema_case_budget_reached')
            break
        operation = result.ok()
        if operation is None:
            gaps.append('unsupported_schema_operation')
            continue
        if graphql_mode and not operation.label.startswith(schema.client_schema.query_type.name + '.'):
            gaps.append('graphql_mutation_requires_disposable_inputs')
            continue
        if not graphql_mode and operation.method.upper() not in ('GET', 'HEAD', 'OPTIONS'):
            gaps.append('schema_state_change_requires_disposable_inputs')
            continue

        modes = [schemathesis.GenerationMode.POSITIVE] if graphql_mode else list(schemathesis.GenerationMode)
        for mode in modes:
            @settings(max_examples=3, derandomize=True, database=None, deadline=None,
                      phases=[Phase.generate], suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much])
            @given(case=operation.as_strategy(generation_mode=mode))
            def collect(case):
                kwargs = schema.as_transport_kwargs(case, base_url=origin, headers={})
                url = kwargs['url']
                if kwargs.get('params'):
                    url += ('&' if '?' in url else '?') + urlencode(kwargs['params'], doseq=True)
                # Schemas cannot introduce credentials or an outbound destination.
                generated = {'method': case.method.upper(), 'url': url, 'generation_mode': mode.value}
                if not graphql_mode:
                    responses = document.get('paths', {}).get(operation.path, {}).get(operation.method.lower(), {}).get('responses', {})
                    generated['expected_statuses'] = list(responses)[:32]
                if graphql_mode:
                    from graphql import parse, OperationDefinitionNode, OperationType
                    payload = kwargs.get('json', {})
                    operations = [node for node in parse(payload.get('query', '')).definitions if isinstance(node, OperationDefinitionNode)]
                    if len(operations) != 1 or operations[0].operation != OperationType.QUERY:
                        raise ValueError('graphql_query_required')
                    generated.update(url=origin, headers={'Content-Type': 'application/json'}, data=json.dumps(payload))
                cases.append(generated)

            try:
                collect()
            except Unsatisfiable:
                gaps.append('schema_generation_mode_unavailable')
    return {'cases': cases[:12], 'gaps': sorted(set(gaps))}


if __name__ == '__main__':
    if sys.argv[1] == '--introspection-query':
        from graphql import get_introspection_query
        print(json.dumps({'query': get_introspection_query(descriptions=False)}))
        raise SystemExit(0)
    raw = Path(sys.argv[1]).read_text()
    if len(raw) > 256 * 1024:
        raise ValueError('schema_size_limit')
    print(json.dumps(generate(json.loads(raw), sys.argv[2])))
