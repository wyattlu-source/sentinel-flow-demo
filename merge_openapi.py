import requests, json, re

NGROK = 'https://arborescent-actorly-carroll.ngrok-free.dev'

# ── Fetch both specs ──────────────────────────────────────────────────────────
sc = requests.get('http://localhost:8010/openapi.json', timeout=5).json()
bd = requests.get('http://localhost:8006/openapi.json', timeout=5).json()

# ── Rename conflicting operationIds in blackduck spec ─────────────────────────
BD_RENAME = {
    'getScanStatus': 'getBDScanStatus',                                          # conflicts with scan-coordinator
    'listProjects': 'listBDProjects',                                            # conflicts with scan-coordinator
    'webhook_scan_complete_webhook_scan_complete_post': 'receiveScanWebhook',    # ugly auto-generated name
}

# ── Clean operationId overrides (auto-generated ugly names) ──────────────────
SC_OVERRIDE = {
    'list_scans_scan_list_get':  'listScans',
    'health_health_get':         'healthCheck',
}

# ── Build combined spec ───────────────────────────────────────────────────────
combined = {
    'openapi': '3.0.3',
    'info': {
        'title':       'SentinelFlow Security Platform',
        'description': (
            'Unified security scan platform: trigger SAST + SCA scans, '
            'query vulnerabilities and BOM from Black Duck, '
            'and request AI-powered auto-fix via Claude Code.'
        ),
        'version': '1.0.0',
    },
    'servers': [{'url': NGROK, 'description': 'SentinelFlow (ngrok)'}],
    'paths': {},
    'components': {'schemas': {}},
}

# Add scan-coordinator paths (fix operationIds)
for path, item in sc.get('paths', {}).items():
    new_item = {}
    for method, op in item.items():
        op = dict(op)
        oid = op.get('operationId', '')
        if oid in SC_OVERRIDE:
            op['operationId'] = SC_OVERRIDE[oid]
        new_item[method] = op
    combined['paths'][path] = new_item

# Add blackduck paths (skip /health duplicate, rename conflicting operationIds)
for path, item in bd.get('paths', {}).items():
    if path == '/health':
        continue
    if path in combined['paths']:
        continue
    new_item = {}
    for method, op in item.items():
        op = dict(op)
        oid = op.get('operationId', '')
        if oid in BD_RENAME:
            op['operationId'] = BD_RENAME[oid]
        new_item[method] = op
    combined['paths'][path] = new_item

# Merge schemas
for name, schema in sc.get('components', {}).get('schemas', {}).items():
    combined['components']['schemas'][name] = schema
for name, schema in bd.get('components', {}).get('schemas', {}).items():
    combined['components']['schemas'][name] = schema

# ── Fix OpenAPI 3.1 → 3.0.3 incompatibilities (recursive) ────────────────────
def fix_schema(obj):
    """
    Recursively fix:
    1. anyOf: [X, {type: null}]  →  X  (nullable in 3.0 sense, just drop null)
    2. 'examples' list in schema objects  →  'example' (first item) or removed
       (in 3.0, 'examples' is only valid in MediaType/Parameter, not Schema)
    """
    if isinstance(obj, list):
        return [fix_schema(i) for i in obj]
    if not isinstance(obj, dict):
        return obj

    # Handle anyOf with null
    if 'anyOf' in obj:
        non_null = [s for s in obj['anyOf'] if s != {'type': 'null'}]
        has_null = len(non_null) < len(obj['anyOf'])
        if has_null and len(non_null) == 1:
            # Flatten: merge the single non-null schema into this object
            merged = {k: v for k, v in obj.items() if k != 'anyOf'}
            merged.update(non_null[0])
            return fix_schema(merged)

    # Handle 'examples' (list) in schema context → convert to 'example'
    result = {}
    for k, v in obj.items():
        if k == 'examples' and isinstance(v, list):
            if v:
                result['example'] = fix_schema(v[0])
            # else drop it
        else:
            result[k] = fix_schema(v)
    return result

combined = fix_schema(combined)

# ── Validate: no duplicate operationIds ───────────────────────────────────────
seen = {}
for path, item in combined['paths'].items():
    for method, op in item.items():
        oid = op.get('operationId', '')
        if oid in seen:
            print(f'ERROR duplicate operationId: {oid}  ({seen[oid]}  vs  {method.upper()} {path})')
        else:
            seen[oid] = f'{method.upper()} {path}'

# ── Report ────────────────────────────────────────────────────────────────────
paths = sorted(combined['paths'].keys())
print(f'Total endpoints: {len(paths)}')
for p in paths:
    for method, op in combined['paths'][p].items():
        print(f'  [{method.upper()}] {p}  ({op.get("operationId","")})')

out = 'scan-coordinator/scan-coordinator-openapi.json'
with open(out, 'w', encoding='utf-8') as f:
    json.dump(combined, f, ensure_ascii=False, indent=2)
print(f'\nSaved: {out}  ({len(seen)} operations)')
