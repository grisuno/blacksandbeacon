# Recipe: Reduce File Complexity

Target hotspot: `c2/server.py`
(complexity 0.3, centrality 1.0)

1. Read dependents: `grep -n 'c2/server.py' readmenator-agent/ARCHITECTURE*.md`
2. Extract functions/classes into new files in the same subsystem
3. Update imports
4. Regenerate: `readmenator .`
