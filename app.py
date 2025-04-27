from flask import Flask, render_template, redirect, url_for, request
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = 'secret_key'

login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'

# Database with passwords stored and roles assigned
users = {
    'Diana': {'password': generate_password_hash('Password'), 'role': 'admin'},
    'Adri': {'password': generate_password_hash('Summer25'), 'role': 'user'}
}

# User clase
class User(UserMixin):
    def __init__(self, username, role):
        self.id = username
        self.role = role

# Load user from session
@login_manager.user_loader
def load_user(user_id):
    # Checks that the user exists and gives them their role
    user_data = users.get(user_id)
    if user_data:
        return User(user_id, user_data['role'])
    return None

# Main protected route
@app.route('/')
@login_required
def home():
    return render_template('login.html.jinja2')

# Login path
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']  # Process user submitted
        password = request.form['password']  # Process password submitted

        # Validate if the submitted data exists and verify the password
        if username in users and check_password_hash(users[username]['password'], password):
            user = User(username, users[username]['role'])
            login_user(user)
            # Redirect based on user role
            if user.role == 'admin':
                return redirect(url_for('admin_panel'))
            elif user.role == 'user':
                return redirect(url_for('user_panel'))
        
                        # The user or password given aren't in the database
        return render_template("error.html.jinja2", error_code=401, 
                               error_message="Invalid Credentials (username or password is wrong)!"), 401
    return render_template('login.html.jinja2')

# Admin panel
@app.route('/admin')
@login_required
def admin_panel():
    if current_user.role != 'admin':
        return "Access denied", 403
    return render_template('admin.html.jinja2', name=current_user.id)

# User panel
@app.route('/user')
@login_required
def user_panel():
    return render_template('user.html.jinja2', name=current_user.id)

# logout path
@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True)