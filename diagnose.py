# diagnose.py
import json
from pathlib import Path

for pkg in ['flask', 'django', 'cryptography']:
    path = Path(f'deptrees/{pkg}_tree.json')
    with open(path) as f:
        tree = json.load(f)
    
    print(f"\n=== {pkg}_tree.json ===")
    print(f"Type: {type(tree)}, Length: {len(tree)}")
    
    if isinstance(tree, list):
        for i, entry in enumerate(tree):
            name = entry.get('package_name', 'UNKNOWN')
            deps = entry.get('dependencies', [])
            print(f"  [{i}] package_name='{name}', dependencies={len(deps)}")
    elif isinstance(tree, dict):
        print(f"  Keys: {list(tree.keys())[:5]}")