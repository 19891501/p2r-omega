# Hooks

No project hook is installed.

`.git/hooks/` still contains only Git's unused samples. Nothing there runs the suite, fetches code, or signs a release.

Tests and `assurance/` do not download or execute remote code. `scripts/mutation_campaign.py` copies this tree into a temp directory and runs `pytest` there.
