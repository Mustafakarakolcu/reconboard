import pytest

from reconboard import db


@pytest.fixture()
def session(tmp_path):
    db.init(f"sqlite:///{tmp_path / 'test.db'}")
    with db.session() as s:
        yield s
