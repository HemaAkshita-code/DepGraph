"""
Set the password for the first admin account, so someone can log in.
Usage:  python create_admin.py
"""
import getpass

from app import database
from app.auth import password_hash


def main():
    email = input("Admin email: ").strip().lower()
    password = getpass.getpass("New password (min 8 characters): ")

    if len(password) < 8:
        print("Password too short.")
        return

    connection = database.get_connection()
    cursor = connection.cursor()
    try:
        cursor.execute(
            """
            UPDATE users
            SET password_hash = :new_hash,
                must_change_password = 'N'
            WHERE email = :email
              AND system_role = 'ADMIN'
              AND is_active = 'Y'
            """,
            {"new_hash": password_hash.hash(password), "email": email},
        )

        if cursor.rowcount == 0:
            print("No active ADMIN user with that email.")
            connection.rollback()
            return

        connection.commit()
        print("Admin password set. You can now log in.")

    finally:
        cursor.close()
        connection.close()


if __name__ == "__main__":
    main()
