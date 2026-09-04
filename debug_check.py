# debug_check.py
import pickle
from pathlib import Path

for pkg in ['flask', 'django', 'cryptography']:
    G = pickle.load(open(f'graphs/{pkg}_graph.pkl', 'rb'))
    print(f"\n=== {pkg} ===")
    print(f"Nodes: {G.number_of_nodes()}, Edges: {G.number_of_edges()}")
    
    cve_nodes = [(n, G.nodes[n]['max_cvss'], G.nodes[n]['cve_count']) 
                 for n in G.nodes() 
                 if G.nodes[n].get('cve_count', 0) > 0]
    
    print(f"Nodes with CVEs: {len(cve_nodes)}")
    for n, cvss, count in cve_nodes[:5]:
        print(f"  {n}: {count} CVEs, max_cvss={cvss}")
    
    # Sample 3 nodes to see what data they have
    nodes = list(G.nodes())[:5]
    for n in nodes:
        print(f"  sample node '{n}': {dict(G.nodes[n])}")