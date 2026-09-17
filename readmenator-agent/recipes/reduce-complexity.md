# Recipe: Reduce File Complexity

Target hotspot: `beacon5.c`
(complexity 0.4, centrality 1.0)

1. Read dependents: `grep -n 'beacon5.c' readmenator-agent/ARCHITECTURE.md`
2. Extract functions/classes into new files in the same subsystem
3. Update imports
4. Regenerate: `readmenator .`
