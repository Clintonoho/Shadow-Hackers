from flask import Flask, render_template, request, redirect, url_for, session
from flask_wtf import FlaskForm
from wtforms import RadioField, SubmitField, StringField, PasswordField
from wtforms.validators import DataRequired
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import datetime

app = Flask(__name__)
app.secret_key = 'supersecretkey123'
app.config['WTF_CSRF_SECRET_KEY'] = 'anothersecret'

ADMIN_USERNAME = 'admin'
ADMIN_PASSWORD_HASH = generate_password_hash('admin123')

quiz_modules = {
    "phishing": {
        "title": "Phishing Awareness Quiz",
        "questions": [
            {"question": "What is phishing?", "choices": ["A scam email", "A fishing trip", "A new app"], "answer": "A scam email", "explanation": "Phishing is when attackers send fake emails to steal personal info."},
            {"question": "What should you check in suspicious emails?", "choices": ["Spelling errors", "Sender address", "All of the above"], "answer": "All of the above", "explanation": "Scam emails often have multiple red flags."},
            {"question": "Clicking unknown links in emails is...", "choices": ["Safe", "Risky", "Fun"], "answer": "Risky", "explanation": "Clicking unknown links may lead to phishing websites."},
            {"question": "Legit companies ask for your password via email?", "choices": ["Yes", "No", "Sometimes"], "answer": "No", "explanation": "Reputable companies never ask for credentials via email."},
            {"question": "Best action for a suspicious email?", "choices": ["Click it", "Reply", "Delete/report"], "answer": "Delete/report", "explanation": "Always delete or report phishing attempts."}
        ]
    },
    "smishing": {
        "title": "Smishing Awareness Quiz",
        "questions": [
            {"question": "What is smishing?", "choices": ["SMS scams", "Social media apps", "Fishing with smart devices"], "answer": "SMS scams", "explanation": "Smishing is phishing via SMS text messages."},
            {"question": "Should you click links in unexpected texts?", "choices": ["Yes", "No"], "answer": "No", "explanation": "Never click on links from unknown sources."},
            {"question": "Common smishing tactic?", "choices": ["Urgency", "Prize offers", "Both"], "answer": "Both", "explanation": "They use urgency or bait to get you to click."},
            {"question": "Who should you contact if unsure about a text?", "choices": ["The sender", "Your bank directly", "Police"], "answer": "Your bank directly", "explanation": "Contact your provider directly using a trusted number."},
            {"question": "Smishing can lead to...", "choices": ["Malware", "Identity theft", "All of the above"], "answer": "All of the above", "explanation": "Smishing can steal data, install malware, or worse."}
        ]
    },
    "passwords": {
        "title": "Password Safety Quiz",
        "questions": [
            {"question": "Best password practice?", "choices": ["123456", "Pet’s name", "Long & unique"], "answer": "Long & unique", "explanation": "Long and unique passwords are more secure."},
            {"question": "Reusing passwords is...", "choices": ["Safe", "Risky", "Recommended"], "answer": "Risky", "explanation": "If one site is hacked, your other accounts are exposed."},
            {"question": "Password managers are...", "choices": ["Helpful", "Untrustworthy", "Only for experts"], "answer": "Helpful", "explanation": "They help you manage strong passwords safely."},
            {"question": "Which is strongest?", "choices": ["Password1", "QwEr123!", "HorseBatteryStaple99!"], "answer": "HorseBatteryStaple99!", "explanation": "Passphrases with symbols are hardest to crack."},
            {"question": "You should update passwords...", "choices": ["Never", "Only if hacked", "Regularly"], "answer": "Regularly", "explanation": "Changing passwords reduces your risk."}
        ]
    },
    "techsupport": {
        "title": "Fake Tech Support Quiz",
        "questions": [
            {"question": "You get a pop-up saying 'Call Microsoft!' What should you do?", "choices": ["Call it", "Ignore/close it", "Download antivirus from it"], "answer": "Ignore/close it", "explanation": "Real companies don’t alert through pop-ups."},
            {"question": "Tech support scammers ask for...", "choices": ["Remote access", "Gift cards", "All of the above"], "answer": "All of the above", "explanation": "They ask for anything they can exploit."},
            {"question": "Best place to get help with computer problems?", "choices": ["Pop-up", "Search random site", "Official provider or local tech"], "answer": "Official provider or local tech", "explanation": "Use a trusted provider or local technician."},
            {"question": "You paid a scammer, now what?", "choices": ["Ignore it", "Contact your bank", "Email the scammer"], "answer": "Contact your bank", "explanation": "Act quickly to limit financial loss."},
            {"question": "True or False: Microsoft will call you first.", "choices": ["True", "False"], "answer": "False", "explanation": "Tech companies don’t call customers out of the blue."}
        ]
    },
    "popups": {
        "title": "Pop-up Scam Awareness Quiz",
        "questions": [
            {"question": "Pop-ups claiming you have a virus are usually...", "choices": ["Helpful", "Scams", "Official alerts"], "answer": "Scams", "explanation": "These are fake alerts to scare you."},
            {"question": "Best thing to do with suspicious pop-up?", "choices": ["Click it", "Download the fix", "Close browser"], "answer": "Close browser", "explanation": "Exit the browser safely."},
            {"question": "Pop-ups often appear when...", "choices": ["Browsing safe sites", "Visiting sketchy websites"], "answer": "Visiting sketchy websites", "explanation": "Shady sites often serve scam ads."},
            {"question": "What should you never do on a pop-up?", "choices": ["Enter credit card", "Read text", "Look at the logo"], "answer": "Enter credit card", "explanation": "Pop-ups are not secure."},
            {"question": "You can block pop-ups by...", "choices": ["Closing your laptop", "Enabling pop-up blocker", "Clicking all of them quickly"], "answer": "Enabling pop-up blocker", "explanation": "Use browser settings to reduce risk."}
        ]
    }
}

@app.route('/')
def welcome():
    return render_template('index.html')

@app.route('/modules')
def module_list():
    return render_template('modules.html', modules=quiz_modules)

@app.route('/quiz/<module>', methods=['GET', 'POST'])
def quiz(module):
    if module not in quiz_modules:
        return "Module not found", 404

    class DynamicQuizForm(FlaskForm):
        name = StringField("Your Name", validators=[DataRequired()])
    
    for i, q in enumerate(quiz_modules[module]["questions"]):
        setattr(DynamicQuizForm, f'q{i}',
                RadioField(q["question"],
                           choices=[(c, c) for c in q["choices"]],
                           validators=[DataRequired()]))

    setattr(DynamicQuizForm, 'submit', SubmitField('Submit Quiz'))
    form = DynamicQuizForm()

    if form.validate_on_submit():
        name = form.name.data
        score = 0
        total_questions = len(quiz_modules[module]["questions"])
        answers = {}

        for i, q in enumerate(quiz_modules[module]["questions"]):
            qid = f'q{i}'
            user_answer = form.data[qid]
            correct_answer = q['answer']
            if user_answer == correct_answer:
                score += 1
            answers[qid] = user_answer

        session[f'{module}_feedback'] = {
            "answers": answers,
            "name": name,
            "score": score,
            "total": total_questions
        }

        conn = sqlite3.connect('seniors.db')
        cursor = conn.cursor()
        cursor.execute("INSERT INTO quiz_results (name, score, total_questions, date_taken) VALUES (?, ?, ?, ?)",
                       (name, score, total_questions, datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
        conn.commit()
        conn.close()

        return redirect(url_for('results', module=module))

    return render_template('quiz.html', form=form, title=quiz_modules[module]['title'])

@app.route('/results/<module>')
def results(module):
    if module not in quiz_modules:
        return "Module not found", 404

    feedback_data = session.get(f'{module}_feedback', {})
    answers = feedback_data.get("answers", {})
    name = feedback_data.get("name", "Unknown")
    score = feedback_data.get("score", 0)
    total = feedback_data.get("total", 0)

    feedback = []
    for i, q in enumerate(quiz_modules[module]["questions"]):
        qid = f'q{i}'
        user_answer = answers.get(qid)
        correct = q['answer']
        is_correct = user_answer == correct
        feedback.append({
            'question': q['question'],
            'user_answer': user_answer,
            'correct_answer': correct,
            'is_correct': is_correct,
            'explanation': q['explanation']
        })

    return render_template('results.html', name=name, score=score, total=total, feedback=feedback, module=module)

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    class LoginForm(FlaskForm):
        username = StringField("Username", validators=[DataRequired()])
        password = PasswordField("Password", validators=[DataRequired()])
        submit = SubmitField("Login")

    form = LoginForm()
    error = None
    if form.validate_on_submit():
        if form.username.data == ADMIN_USERNAME and check_password_hash(ADMIN_PASSWORD_HASH, form.password.data):
            session['admin_logged_in'] = True
            return redirect('/admin_dashboard')
        else:
            error = "Invalid username or password."

    return render_template('admin_login.html', form=form, error=error)

@app.route('/admin_dashboard')
def admin_dashboard():
    if not session.get('admin_logged_in'):
        return redirect('/admin_login')
    conn = sqlite3.connect('seniors.db')
    cursor = conn.cursor()
    cursor.execute("SELECT name, score, total_questions, date_taken FROM quiz_results ORDER BY date_taken DESC")
    results = cursor.fetchall()
    conn.close()
    return render_template('admin_dashboard.html', results=results)

@app.route('/admin_logout')
def admin_logout():
    session.clear()
    return redirect('/')

@app.route('/learn')
def learn():
    return render_template('learn.html')

if __name__ == '__main__':
    app.run(debug=True)



