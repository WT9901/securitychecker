from __future__ import annotations

import pytest

from secure_checker import create_app


@pytest.fixture
def app():
    app = create_app()
    app.config.update(
        TESTING=True,
        SECRET_KEY="test-secret-key",
    )
    return app


@pytest.fixture
def client(app):
    return app.test_client()
