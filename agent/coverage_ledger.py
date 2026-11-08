"""Evidence-indexed coverage, including explicit gaps for unverified test classes."""
from collections import Counter
import hashlib
import json
from pathlib import Path
import time
from urllib.parse import urlsplit

from web_tools import record


def build(scope, runs, directory=Path('/work')):
    evidence = {}
    for path in sorted((directory / 'http-evidence').glob('*.json')):
        try:
            item = json.loads(path.read_text())
            if type(item.get('id')) is int and not item.get('login'):
                evidence[item['id']] = item
        except (OSError, ValueError, TypeError):
            continue
    units = {}
    for item in evidence.values():
        url = item.get('url', '')
        parsed = urlsplit(url)
        if parsed.scheme + '://' + parsed.netloc not in scope['origins']:
            continue
        account = item.get('account', 'testing') if item.get('authenticated') else 'anonymous'
        identity = [url, item['method'], account, 'http_observation']
        key = hashlib.sha256(json.dumps(identity, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()
        unit = units.setdefault(key, {'id': key, 'url': url, 'method': item['method'], 'account': account,
                                     'class': 'http_observation', 'state': 'blocked', 'evidence_ids': [],
                                     'reason': 'request_unavailable'})
        if not item.get('error') and item.get('status'):
            unit.update(state='tested', reason='Recorded request and response. Vulnerability-class coverage needs its own controls.')
            unit['evidence_ids'] = (unit['evidence_ids'] + [item['id']])[-24:]
    # A response establishes an observation. It cannot close every vulnerability
    # class. Retain these obligations until specific controls support closure.
    for origin in scope['origins']:
        contexts = ['anonymous', 'testing'] if scope.get('authentication') else ['anonymous']
        if scope.get('account_policy') is not None:
            contexts.append('reference')
        for account in contexts:
            for category in ['input_handling', 'authorization', 'session_lifecycle', 'browser_execution']:
                identity = [origin + '/', 'GET', account, category]
                key = hashlib.sha256(json.dumps(identity, ensure_ascii=False, separators=(',', ':')).encode()).hexdigest()
                units[key] = {'id': key, 'url': origin + '/', 'method': 'GET', 'account': account,
                              'class': category, 'state': 'deferred', 'evidence_ids': [],
                              'reason': 'Review candidate-specific controls and remaining paths. Recorded traffic alone cannot establish complete coverage.'}
    values = sorted(units.values(), key=lambda unit: (unit['state'] == 'tested', unit['id']))
    unit_counts = dict(Counter(unit['state'] for unit in values))
    omitted = max(0, len(values) - 40)
    # Keep the public report bounded. The complete request evidence is separate.
    values = values[:40]
    result = {'version': 1, 'summary_state': 'recorded', 'unit_counts': unit_counts, 'units': values, 'omitted_units': omitted,
              'tool_time_ms': sum(r['duration_ms'] for r in runs),
              'cost_source': 'provider_usage_in_execution_receipt'}
    (directory / 'coverage-ledger.json').write_text(json.dumps(result))
    while len(json.dumps(result).encode()) > 23 * 1024 and result['units']:
        result['units'].pop()
        result['omitted_units'] += 1
    (directory / 'coverage-ledger.json').write_text(json.dumps(result))
    refs = sorted({ref for unit in values for ref in unit['evidence_ids']})
    return record('patchriot-coverage', '1', ['recorded-evidence'], time.monotonic(), int(time.time()),
                  refs, json.dumps(result))
