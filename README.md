Selva

Introduction
An online mental health diary management system for clients to submit diary entries to therapists.


Getting Started

Installation
1. Clone the repository: 
git clone https://github.com/your_username/your_project.git
cd your_project

2. Activate the 'selvavenv' virtual environment:
source selvavenv/bin/activate
 # On Windows, use `selvavenv\Scripts\activate`

3. Install the required dependencies:
pip install -r requirements.txt

4. Database Setup
flask db init
flask db migrate -m "Initial migration"
flask db upgrade

5. Running the Application
python app.py 

The application will be accessible at http://127.0.0.1:5000 in your web browser.