"""Generate bounded schema cases offline. All target I/O belongs to the broker."""
import json
from pathlib import Path
import re
import sys
from urllib.parse import urlencode, urljoin, urlsplit, urlunsplit

from web_tools import allowed

READ_METHODS = ('GET', 'HEAD', 'OPTIONS')
UNSAFE_READ = re.compile(r'(?:^|[/_-])(logout|signout|delete|destroy|reset|revoke|unsubscribe)(?:$|[/_.?-])', re.I)


def base_candidates(document, schema_url, observed_urls):
    """Declared servers first; inferred mounts still need HTTP controls."""
    parsed = urlsplit(schema_url)
    origin = parsed.scheme + '://' + parsed.netloc

    def checked(raw):
        if not isinstance(raw, str) or not raw or '{' in raw or '}' in raw:
            return None
        url = urljoin(schema_url, raw)
        parts = urlsplit(url)
        if not allowed(origin, url) or parts.query or '..' in parts.path.split('/'):
            return None
        return url.rstrip('/')

    if 'servers' in document and document['servers']:
        if not isinstance(document['servers'], list):
            raise ValueError('schema_servers_invalid')
        values = []
        for server in document['servers'][:8]:
            if not isinstance(server, dict):
                continue
            raw = server.get('url', '')
            if not isinstance(raw, str) or not isinstance(server.get('variables', {}), dict):
                continue
            for name, variable in server.get('variables', {}).items():
                if not isinstance(variable, dict):
                    continue
                default = variable.get('default')
                if isinstance(default, str):
                    raw = raw.replace('{' + name + '}', default)
            if base := checked(raw):
                values.append(base)
        return list(dict.fromkeys(values))[:4], True
    if 'swagger' in document and ('basePath' in document or 'host' in document):
        if document.get('host', parsed.netloc) != parsed.netloc:
            return [], True
        base = checked(document.get('basePath', '/'))
        return ([base] if base else []), True
    if not isinstance(document.get('paths', {}), dict):
        raise ValueError('schema_paths_invalid')
    paths = [path for path, item in document.get('paths', {}).items()
             if isinstance(item, dict) and 'get' in item and '{' not in path and path != '/'
             and path.startswith('/') and not UNSAFE_READ.search(path)]
    candidates = []
    for observed in observed_urls:
        if not allowed(origin, observed):
            continue
        observed_path = urlsplit(observed).path
        for path in paths:
            if observed_path.endswith(path):
                candidates.append(origin + observed_path[:-len(path)])
    parent = urlunsplit((parsed.scheme, parsed.netloc, parsed.path.rsplit('/', 1)[0], '', ''))
    candidates.extend([parent, origin])
    return list(dict.fromkeys(base for raw in candidates if (base := checked(raw))))[:4], False


def base_probe_paths(document, base, observed_urls):
    paths = [path for path, item in document.get('paths', {}).items()
             if isinstance(item, dict) and 'get' in item and '{' not in path
             and path.startswith('/') and not UNSAFE_READ.search(path)]
    return sorted(paths, key=lambda path: base + path not in observed_urls)[:2]


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


def generate(document, origin, max_cases=48, methods=READ_METHODS):
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
    max_cases = max(1, min(48, int(max_cases)))
    cases, gaps, operations, deferred = [], [], [], []
    total_operations = 0
    for result in schema.get_all_operations():
        total_operations += 1
        operation = result.ok()
        if operation is None:
            gaps.append('unsupported_schema_operation')
            continue
        if graphql_mode and not operation.label.startswith(schema.client_schema.query_type.name + '.'):
            deferred.append({'operation': operation.label, 'reason': 'mutation_requires_agent_review'})
            continue
        if not graphql_mode:
            path_item = document.get('paths', {}).get(operation.path, {})
            definition = path_item.get(operation.method.lower(), {})
            if path_item.get('servers') or definition.get('servers'):
                # This sample has one verified base. Do not rewrite an operation
                # with its own destination to that base and claim it was tested.
                deferred.append({'operation': operation.label, 'reason': 'operation_server_requires_agent_review'})
                continue
        if not graphql_mode and (operation.method.upper() not in READ_METHODS
                                 or operation.method.upper() not in methods
                                 or UNSAFE_READ.search(operation.path)):
            deferred.append({'operation': operation.label, 'reason': 'requires_agent_review_and_permission'})
            continue
        operations.append(operation)

    # Cover distinct endpoints before spending the sample on variations of the
    # first one. Generation stays offline; the broker owns every target request.
    sampled, unavailable_modes = False, 0
    modes = [schemathesis.GenerationMode.POSITIVE]
    if not graphql_mode:
        modes.append(schemathesis.GenerationMode.NEGATIVE)
    for mode in modes:
        for operation in operations:
            if len(cases) >= max_cases:
                sampled = True
                break
            @settings(max_examples=1, derandomize=True, database=None, deadline=None,
                      phases=[Phase.generate], suppress_health_check=[HealthCheck.too_slow, HealthCheck.filter_too_much])
            @given(case=operation.as_strategy(generation_mode=mode))
            def collect(case):
                kwargs = schema.as_transport_kwargs(case, base_url=origin, headers={})
                url = kwargs['url']
                if kwargs.get('params'):
                    url += ('&' if '?' in url else '?') + urlencode(kwargs['params'], doseq=True)
                # Schemas cannot introduce credentials or an outbound destination.
                generated = {'method': case.method.upper(), 'url': url, 'generation_mode': mode.value,
                             'operation': operation.label}
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
                unavailable_modes += 1
    if operations and not cases:
        gaps.append('schema_no_cases_generated')
    return {'cases': cases, 'gaps': sorted(set(gaps)),
            'sampling_limits': ['schema_case_sample_limit'] if sampled else [],
            'operations_total': total_operations, 'operations_eligible': len(operations),
            'operations_selected': len({case['operation'] for case in cases}),
            'case_limit': max_cases, 'generation_modes_unavailable': unavailable_modes,
            'deferred_operations_count': len(deferred), 'deferred_operations': deferred[:16],
            'limitations': ['State-changing operations are left for agent investigation under the existing scope; a schema never grants permission to submit them.']}


if __name__ == '__main__':
    if sys.argv[1] == '--introspection-query':
        from graphql import get_introspection_query
        print(json.dumps({'query': get_introspection_query(descriptions=False)}))
        raise SystemExit(0)
    raw = Path(sys.argv[1]).read_text()
    if len(raw) > 256 * 1024:
        raise ValueError('schema_size_limit')
    print(json.dumps(generate(json.loads(raw), sys.argv[2], int(sys.argv[3]) if len(sys.argv) > 3 else 48,
                              sys.argv[4].split(',') if len(sys.argv) > 4 else READ_METHODS)))
