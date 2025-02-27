import os
from app import create_app

app = create_app()

if __name__ == "__main__":
    app.run(os.getenv("FLASK_HOST", "127.0.0.1"), os.getenv("FLASK_PORT", "5000"))
