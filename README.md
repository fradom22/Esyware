# Esyware

Esyware is a lightweight web application designed to manage structured data
through a simple and intuitive web interface.
The project focuses on backend logic, database initialization, and classic
server-rendered web architecture.

## Tech Stack
- **Backend:** Python
- **Web Framework:** Flask
- **Database:** Relational database (SQL)
- **Frontend:** HTML, CSS, JavaScript
- **Tools:** Git

## Project Structure
Esyware/
├── app.py               # Main application entry point
├── init_db_once.py      # One-time database initialization script
├── requirements.txt     # Python dependencies
├── templates/           # HTML templates
└── static/              # CSS, JavaScript, and static assets

## Features
- Server-side rendered web pages
- Database initialization via dedicated script
- Clear separation between application logic and presentation layer
- Simple and maintainable project structure

## Getting Started

### Prerequisites
- Python 3.10 or newer

### Installation
git clone https://github.com/fradom22/Esyware.git
cd Esyware
python -m venv .venv
pip install -r requirements.txt

### Database Initialization
Run this command once before starting the application:
python init_db_once.py

### Run the Application
python app.py

Open your browser at:
http://127.0.0.1:5000

## Notes
This project is intended as a backend-focused demonstration of a Python web
application with database integration.
