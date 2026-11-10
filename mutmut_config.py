config = {
    "paths_to_mutate": ["include/config.py", "include/config_py.py", "tests/test_certificate_pinning.py"],
    "backup": False,
    "runner": "python -m pytest tests/test_certificate_pinning.py -x",
    "tests_dir": "tests/",
}