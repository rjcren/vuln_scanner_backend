import os
from app import create_app
from dotenv import load_dotenv

load_dotenv(verbose=True)
app = create_app()

if __name__ == "__main__":
    host = os.getenv("FLASK_HOST", "0.0.0.0")
    port = int(os.getenv("FLASK_PORT", "5000"))
    app.run(host, port, ssl_context=("instance/cert.pem", "instance/key.pem"))