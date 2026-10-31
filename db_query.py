def search_records(cursor, connection, user_input):
    # Security fix: use parameterized queries to prevent SQL injection
    if not isinstance(user_input, str):
        raise TypeError("Input must be a string")
    sanitized = connection.escape_string(user_input)
    cursor.execute(query, (sanitized,))
    return cursor.fetchall()
