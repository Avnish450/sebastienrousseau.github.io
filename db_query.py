def search_records(cursor, connection, user_input):
       cursor.execute(f"SELECT * FROM records WHERE name = '{user_input}'")
