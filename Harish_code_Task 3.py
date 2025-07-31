# secure_app.py
from flask import Flask, request, render_template_string
import sqlite3
import os # Import os module for path handling

app = Flask(__name__)

# Define the database path relative to the application's directory
# This ensures the database is created/accessed in the correct location
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DATABASE = os.path.join(BASE_DIR, 'users.db')

# --- Database Setup Function ---
def init_db():
    """
    Initializes the SQLite database.
    Creates the 'users' table if it doesn't exist and
    inserts sample user data for demonstration purposes.
    """
    conn = None
    try:
        conn = sqlite3.connect(DATABASE)
        cursor = conn.cursor()
        cursor.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT NOT NULL UNIQUE,
                password TEXT NOT NULL,
                data TEXT
            )
        ''')
        # Insert sample user data.
        # 'OR IGNORE' prevents errors if the users already exist from a previous run.
        cursor.execute("INSERT OR IGNORE INTO users (username, password, data) VALUES (?, ?, ?)",
                       ('admin', 'password123', 'Sensitive admin data for admin user.'))
        cursor.execute("INSERT OR IGNORE INTO users (username, password, data) VALUES (?, ?, ?)",
                       ('testuser', 'testpass', 'Regular user data for testuser.'))
        conn.commit()
        print("Database initialized successfully with sample data.")
    except sqlite3.Error as e:
        print(f"Database initialization error: {e}")
    finally:
        if conn:
            conn.close()

# Initialize database on application startup
# The app_context ensures that operations like database initialization
# are performed within the Flask application's context.
with app.app_context():
    init_db()

# --- HTML Template for Login Page ---
# This template is embedded directly in the Python file for simplicity.
# In a larger application, this would typically be in a separate .html file
# in a 'templates' directory.
LOGIN_HTML = """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>Secure Login Application</title>
    <link href="https://cdn.jsdelivr.net/npm/tailwindcss@2.2.19/dist/tailwind.min.css" rel="stylesheet">
    <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;600&display=swap" rel="stylesheet">
    <style>
        body {
            font-family: 'Inter', sans-serif;
        }
    </style>
</head>
<body class="bg-gray-100 min-h-screen flex items-center justify-center p-4">
    <div class="bg-white p-8 rounded-lg shadow-lg w-full max-w-md">
        <h2 class="text-3xl font-semibold text-center text-gray-800 mb-6">Secure Login</h2>
        <form method="post" class="space-y-4">
            <div>
                <label for="username" class="block text-gray-700 text-sm font-bold mb-2">Username:</label>
                <input type="text" id="username" name="username" required
                       class="shadow appearance-none border rounded-lg w-full py-2 px-3 text-gray-700 leading-tight focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent">
            </div>
            <div>
                <label for="password" class="block text-gray-700 text-sm font-bold mb-2">Password:</label>
                <input type="password" id="password" name="password" required
                       class="shadow appearance-none border rounded-lg w-full py-2 px-3 text-gray-700 mb-3 leading-tight focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent">
            </div>
            <button type="submit"
                    class="w-full bg-green-600 hover:bg-green-700 text-white font-bold py-2 px-4 rounded-lg focus:outline-none focus:shadow-outline transition duration-300 ease-in-out transform hover:scale-105">
                Login
            </button>
        </form>

        {% if message %}
            <div class="mt-6 p-3 rounded-lg text-center
                        {% if 'successful' in message.lower() %}bg-green-100 text-green-700{% else %}bg-red-100 text-red-700{% endif %}">
                <p class="font-medium">{{ message }}</p>
            </div>
        {% endif %}

        {% if user_data %}
            <div class="mt-4 p-3 rounded-lg bg-blue-100 text-blue-700 text-center">
                <p class="font-medium"><strong>Your Data:</strong> {{ user_data }}</p>
            </div>
        {% endif %}
    </div>
</body>
</html>
"""

# --- Login Route ---
@app.route('/', methods=['GET', 'POST'])
def login_secure():
    """
    Handles user login requests.
    Uses parameterized queries to prevent SQL Injection.
    """
    message = None      # Message to display to the user (e.g., login status)
    user_data = None    # Data retrieved for the logged-in user

    if request.method == 'POST':
        # Retrieve username and password from the submitted form
        username = request.form.get('username')
        password = request.form.get('password')

        # Basic input validation: ensure both fields are provided
        if not username or not password:
            message = "Please enter both username and password."
            # Render the template with the error message
            return render_template_string(LOGIN_HTML, message=message, user_data=user_data)

        conn = None
        try:
            # Establish a connection to the SQLite database
            conn = sqlite3.connect(DATABASE)
            cursor = conn.cursor()

            # --- SECURE CODE: Using Parameterized Queries ---
            # The '?' placeholders are used for parameters.
            # The database driver will handle escaping the values,
            # preventing them from being interpreted as SQL commands.
            query = "SELECT data FROM users WHERE username = ? AND password = ?"

            # Execute the query, passing the parameters as a tuple.
            # This is the crucial step for preventing SQL Injection.
            cursor.execute(query, (username, password))

            # Fetch the first matching result (if any)
            result = cursor.fetchone()

            if result:
                # If a user is found, retrieve their associated data
                user_data = result[0]
                message = "Login successful! Welcome."
            else:
                # If no user matches the credentials
                message = "Invalid username or password. Please try again."
        except sqlite3.Error as e:
            # Catch any database-related errors and provide a generic message
            # Avoid exposing specific database error details to the user.
            print(f"Database error during login: {e}") # Log the actual error for debugging
            message = "An internal server error occurred. Please try again later."
        finally:
            # Ensure the database connection is closed, regardless of success or failure
            if conn:
                conn.close()

    # Render the HTML template, passing messages and user data for display
    return render_template_string(LOGIN_HTML, message=message, user_data=user_data)

# --- Application Entry Point ---
if __name__ == '__main__':
    app.run(debug=True, port=5000)
