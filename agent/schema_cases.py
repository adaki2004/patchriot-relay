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
    if schemathesis.__version__ != '4.33.1':
        raise ValueError('schema_version_mismatch')
    check_references(document)
    schema = schemathesis.openapi.from_dict(document, config=schemathesis.Config())
    cases, gaps = [], []
    for result in schema.get_all_operations():
        if len(cases) >= 12:
            gaps.append('schema_case_budget_reached')
            break
        operation = result.ok()
        if operation is None:
            gaps.append('unsupported_schema_operation')
            continue
        if operation.method.upper() not in ('GET', 'HEAD', 'OPTIONS'):
            gaps.append('schema_state_change_requires_disposable_inputs')
            continue

        @settings(max_examples=3, derandomize=True, database=None, deadline=None,
                  phases=[Phase.generate], suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much])
        @given(case=operation.as_strategy())
        def collect(case):
            kwargs = schema.as_transport_kwargs(case, base_url=origin, headers={})
            url = kwargs['url']
            if kwargs.get('params'):
                url += ('&' if '?' in url else '?') + urlencode(kwargs['params'], doseq=True)
            # Schemas cannot introduce credentials or an outbound destination.
            cases.append({'method': case.method.upper(), 'url': url})

        collect()
    return {'cases': cases[:12], 'gaps': sorted(set(gaps))}


if __name__ == '__main__':
    raw = Path(sys.argv[1]).read_text()
    if len(raw) > 256 * 1024:
        raise ValueError('schema_size_limit')
    print(json.dumps(generate(json.loads(raw), sys.argv[2])))
