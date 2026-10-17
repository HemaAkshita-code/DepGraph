from app import database

connection = database.get_connection()

try:
    cursor = connection.cursor()
    cursor.execute("SELECT USER, SYSDATE FROM DUAL")
    result = cursor.fetchone()
    print("Database user:", result[0])
    print("Current date:", result[1])
except Exception as e:
    print(f"Error occurred: {e}")
finally:
    cursor.close()
    connection.close()