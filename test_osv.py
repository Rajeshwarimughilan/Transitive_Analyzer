# test_osv.py
import requests

def test_osv(package, version):
    payload = {
        'package': {'name': package, 'ecosystem': 'PyPI'},
        'version': version
    }
    r = requests.post('https://api.osv.dev/v1/query', json=payload)
    data = r.json()
    vulns = data.get('vulns', [])
    print(f"\n{package}@{version}: {len(vulns)} vulns found")
    for v in vulns[:3]:
        aliases = v.get('aliases', [])
        cves = [a for a in aliases if a.startswith('CVE-')]
        print(f"  {v['id']} -> CVEs: {cves}")

# Test with known vulnerable versions
test_osv('werkzeug', '2.3.7')       # has known CVEs
test_osv('cryptography', '41.0.0')  # has known CVEs
test_osv('django', '4.2.0')         # has known CVEs
test_osv('pillow', '9.5.0')         # has known CVEs