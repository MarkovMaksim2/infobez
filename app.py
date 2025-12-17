import html
import os
from datetime import timedelta

from flask import Flask, jsonify, request
from flask_jwt_extended import (
    JWTManager,
    create_access_token,
    get_jwt_identity,
    jwt_required,
)
from flask_sqlalchemy import SQLAlchemy
import bcrypt

db = SQLAlchemy()


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password_hash = db.Column(db.LargeBinary(60), nullable=False)
    role = db.Column(db.String(20), default="user", nullable=False)

    def set_password(self, password: str) -> None:
        self.password_hash = bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt())

    def check_password(self, password: str) -> bool:
        if not self.password_hash:
            return False
        return bcrypt.checkpw(password.encode("utf-8"), self.password_hash)


class Note(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    author_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    body = db.Column(db.Text, nullable=False)
    author = db.relationship("User", backref="notes", lazy="joined")


def create_app() -> Flask:
    app = Flask(__name__)
    app.config["SQLALCHEMY_DATABASE_URI"] = os.environ.get(
        "DATABASE_URL", "sqlite:///app.db"
    )
    app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
    app.config["JWT_SECRET_KEY"] = os.environ.get(
        "JWT_SECRET_KEY", "change-this-in-prod"
    )
    app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(hours=1)

    db.init_app(app)
    JWTManager(app)

    @app.before_request
    def ensure_json_request():
        if request.method in {"POST", "PUT", "PATCH"} and not request.is_json:
            return jsonify({"error": "JSON body is required"}), 400

    @app.post("/auth/login")
    def login():
        payload = request.get_json(silent=True) or {}
        username = payload.get("username")
        password = payload.get("password")
        if not username or not password:
            return jsonify({"error": "username and password are required"}), 400

        user = User.query.filter_by(username=username).first()
        if not user or not user.check_password(password):
            return jsonify({"error": "invalid credentials"}), 401

        token = create_access_token(
            identity=user.username,
            additional_claims={"role": user.role},
        )
        return jsonify({"access_token": token}), 200

    @app.get("/api/data")
    @jwt_required()
    def secure_data():
        current_user = get_jwt_identity()
        users = User.query.order_by(User.username).all()
        sanitized_users = [
            {"id": u.id, "username": html.escape(u.username), "role": u.role}
            for u in users
        ]
        return jsonify({"requested_by": current_user, "users": sanitized_users})

    @app.post("/api/notes")
    @jwt_required()
    def create_note():
        current_username = get_jwt_identity()
        payload = request.get_json(silent=True) or {}
        body = payload.get("body", "")
        if not body.strip():
            return jsonify({"error": "note body is required"}), 400

        user = User.query.filter_by(username=current_username).first()
        if not user:
            return jsonify({"error": "user not found"}), 404

        sanitized_body = html.escape(body.strip())
        note = Note(author=user, body=sanitized_body)
        db.session.add(note)
        db.session.commit()

        return (
            jsonify(
                {
                    "id": note.id,
                    "author": user.username,
                    "body": note.body,
                }
            ),
            201,
        )

    @app.get("/api/notes")
    @jwt_required()
    def list_notes():
        notes = Note.query.order_by(Note.id.desc()).all()
        serialized = [
            {"id": n.id, "author": html.escape(n.author.username), "body": n.body}
            for n in notes
        ]
        return jsonify({"notes": serialized})

    @app.get("/healthz")
    def healthcheck():
        return jsonify({"status": "ok"}), 200

    with app.app_context():
        db.create_all()
        _seed_default_user()

    return app


def _seed_default_user() -> None:
    if User.query.filter_by(username="admin").first():
        return
    user = User(username="admin", role="admin")
    user.set_password(os.environ.get("DEFAULT_ADMIN_PASSWORD", "P@ssw0rd!"))
    db.session.add(user)
    db.session.commit()


if __name__ == "__main__":
    create_app().run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)))
