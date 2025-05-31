# Expense Tracker

A web application for tracking and sharing expenses with friends and family. Built with Flask and SQLite.

## Features

- User authentication (register, login, logout)
- Add and track personal expenses
- Categorize expenses
- Share expenses with other users
- View expense history and analytics
- Track shared expenses and pending payments

## Setup

1. Create a virtual environment:
```bash
python -m venv venv
```

2. Activate the virtual environment:
- Windows:
```bash
venv\Scripts\activate
```
- Unix/MacOS:
```bash
source venv/bin/activate
```

3. Install dependencies:
```bash
pip install -r requirements.txt
```

4. Initialize the database:
```bash
python app.py
```

5. Access the application:
Open your web browser and navigate to `http://localhost:5000`

## Usage

1. Register a new account or login with existing credentials
2. Add expenses through the "Add Expense" button
3. View your expenses and analytics on the dashboard
4. Share expenses with other users by clicking the "Share" button
5. Track shared expenses and pending payments

## Technologies Used

- Flask - Web framework
- SQLAlchemy - Database ORM
- SQLite - Database
- Bootstrap - Frontend styling
- Flask-Login - User authentication
- Flask-WTF - Form handling

## Security Features

- Password hashing
- User authentication
- CSRF protection
- Secure session management

## Contributing

Feel free to submit issues and enhancement requests! 