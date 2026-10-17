import os
import oracledb

from dotenv import load_dotenv

# Load environment variables from .env
load_dotenv()


def get_connection():

    connection = oracledb.connect(
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        host=os.getenv("DB_HOST"),
        port=int(os.getenv("DB_PORT", "1521")),
        service_name=os.getenv("DB_SERVICE")
    )

    return connection