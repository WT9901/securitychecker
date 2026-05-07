from __future__ import annotations

from flask import Flask

from secure_checker.config import BASE_DIR, get_secret_key
from secure_checker.routes.web import web_bp
from secure_checker.demo import demo_bp


def create_app() -> Flask:
    """Application factory for cleaner architecture and testability."""
    app = Flask(
        __name__,
        template_folder=str(BASE_DIR / "templates"),
        static_folder=str(BASE_DIR / "static"),
        static_url_path="/static",
    )
    app.config["SECRET_KEY"] = get_secret_key()
    app.register_blueprint(web_bp)
    app.register_blueprint(demo_bp)
    return app
