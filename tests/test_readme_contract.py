from pathlib import Path


ROOT = Path(__file__).resolve().parents[1]


def test_readme_documents_the_safe_operator_contract():
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for heading in (
        "## Overview",
        "## Features",
        "## Prerequisites",
        "## Installation and setup",
        "## Verification",
        "## Troubleshooting",
        "## License",
        "## Contributing",
        "## Security",
        "## Architecture",
    ):
        assert readme.count(heading) == 1, f"README must contain one {heading} heading"

    for token in (
        "bash ZeroXSHDW_autosnort-ubuntu.sh --check",
        "python3 -m unittest discover -s tests -p 'test_*.py' -v",
        "full_autosnort.conf.local",
        "Do not commit real oinkcodes.",
        "without running the privileged installer",
        "or requiring a live lab network",
    ):
        assert token in readme, f"README is missing operator contract: {token}"

    assert "## License and Credits" not in readme
    assert "/Users/" not in readme
