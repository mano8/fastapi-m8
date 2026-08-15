"""Version-source parity — A33-version-source-parity.

`fastapi-m8` keeps two version sources: the literal `version = "x.y.z"` in
`[project]` (`pyproject.toml`) and `fastapi_m8/_version.py`'s
`__version__ = "x.y.z"`, re-exported as `fastapi_m8.__version__`. Nothing
enforced that the two agreed — a release could bump one and forget the other,
producing a package whose installed metadata (`importlib.metadata.version`)
disagrees with what `fastapi_m8.__version__` reports at runtime. This locks
the two sources together until the repo converges on a single one (`dynamic`,
the `imgtools_m8` pattern), which the workspace's `A33` version-source-parity
record tracks as the recommended target.
"""

import tomllib
from pathlib import Path

from fastapi_m8 import __version__

REPO_ROOT = Path(__file__).resolve().parents[1]
PYPROJECT = REPO_ROOT / "pyproject.toml"


def test_pyproject_version_matches_runtime_version() -> None:
    """`pyproject.toml`'s `[project].version` must equal `fastapi_m8.__version__`."""
    data = tomllib.loads(PYPROJECT.read_text(encoding="utf-8"))
    pyproject_version = data["project"]["version"]
    assert pyproject_version == __version__, (
        f"pyproject.toml [project].version = {pyproject_version!r} but "
        f"fastapi_m8.__version__ = {__version__!r}; the two declared version "
        "sources have drifted. Update fastapi_m8/_version.py and "
        "pyproject.toml together, or converge on the `dynamic` pattern."
    )
