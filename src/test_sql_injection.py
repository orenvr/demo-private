#!/usr/bin/env python3
"""
Simple SQL injection vulnerability for CodeQL testing
"""
import sqlite3

def vulnerable_query(user_id, username):
    """Function with clear SQL injection vulnerability"""
    
    # Connect to database
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # VULNERABILITY: User input directly concatenated into SQL query
    query = f"SELECT * FROM users WHERE id = {user_id} AND username = '{username}'"
    cursor.execute(query)  # SINK: SQL query with user input
    
    results = cursor.fetchall()
    conn.close()
    
    return results

def another_sql_injection(search_term):
    """Another SQL injection pattern"""
    
    conn = sqlite3.connect('products.db')
    cursor = conn.cursor()
    
    # VULNERABILITY: String formatting with user input
    unsafe_query = "SELECT * FROM products WHERE name LIKE '%" + search_term + "%'"
    cursor.execute(unsafe_query)
    
    return cursor.fetchall()

def main():
    # Test with malicious input
    malicious_id = "1; DROP TABLE users; --"
    malicious_username = "admin' OR '1'='1"
    
    vulnerable_query(malicious_id, malicious_username)
    another_sql_injection("test'; DROP TABLE products; --")

if __name__ == "__main__":
    main()
