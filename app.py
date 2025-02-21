import os
from app import create_app
from app.config import Config

app = create_app(os.getenv("FLASK_ENV") or "development")

if __name__ == "__main__":
    app.run(Config.HOSTNAME, Config.PORT)
