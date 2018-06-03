import os
from pdb import set_trace as st
import hashlib
from flask import Flask, request, abort, jsonify, send_from_directory, send_file, session
from datetime import datetime, timezone

PARENT_DIR = ["/home/victor/scripts", "/home/victor/.config"]

app = Flask(__name__)
app.secret_key = "vbju712gg2"

passwd_attempts = 3


# Expire session variables after 15 minutes(user will have to logon again after this timeout)
@app.before_request
def expire_session():
    from datetime import timedelta
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=15)


def validate_login(passwd_input):
    passwd_input_hash = hashlib.sha256(str.encode(passwd_input))
    passwd_input_hash = passwd_input_hash.hexdigest()
    # Hashed password is in a file "passwd"
    with open("passwd", "r") as pwf:
        passwd_valid = pwf.read().strip()
        if passwd_valid == passwd_input_hash:
            session['logged'] = True
        else:
            global passwd_attempts
            if passwd_attempts == 0:
                invoke_quarantine()
            passwd_attempts -= 1
            print(passwd_attempts)
    # Return the value of session var 'logged' -> return False if variable doesn't exist(valid password hasn't been entered or session has expired)
    return session.get('logged', False)


def list_files(directory):
    files = []
    if os.path.isfile(directory):
        return directory
    try:
        for filename in os.listdir(directory):
            path = os.path.join(directory, filename)
            if os.path.isfile(path):
                files.append({"name": filename, "type": "file"})
            else:
                files.append({"name": filename, "type": "dir"})
    except FileNotFoundError:
        pass # TODO
    return files


@app.route('/<path:dir>')
def fallback(dir):
    if not session.get('logged', False):
        return "Forbidden"
    forbidden = True
    # Check if user is trying to access files under pre-specified directories(PARENT_DIR)
    for d in PARENT_DIR:
        if ("/"+dir).startswith(d):
            forbidden = False
            break
    if forbidden:
        return "Forbidden"
    dir = "/" + dir
    if not os.path.isfile(dir):
        return render_listing(list_files(dir))
    # User has clicked on a file(as in not a directory), this will enable the browser to popup a download dialog for that file
    else:
        return send_file(dir, attachment_filename=dir.split("/")[0])


@app.route('/')
def check_logged():
    if not check_quarantine():
        return user_in_quarantine()
    if session.get('logged', False):
        return index()
    else:
        return logon_page()

def invoke_quarantine():
    global passwd_attempts
    passwd_attempts = 3
    # Create file(or recreate silently)
    open(".quarantine", 'a').close()
    with open(".quarantine", "w") as qw:
        qw.write(datetime.now().strftime("%Y/%m/%d %H:%M:%S"))
    return user_in_quarantine()


def user_in_quarantine():
    return "<p> You are in quarantine. You may try to login soon again. </p>"

# Very lazy method for checking if 5 mins has passed, will not work when hour changes
def check_quarantine():
    try:
        with open(".quarantine", "r") as qr:
            qr_start = qr.read().strip()
            qr_start_date = datetime.strptime(qr_start, "%Y/%m/%d %H:%M:%S").date()
            qr_start_time = datetime.strptime(qr_start, "%Y/%m/%d %H:%M:%S").time()
            if datetime.now().date() == qr_start_date:
                if datetime.now().time().hour > qr_start_time.hour:
                    return True
                else:
                    if datetime.now().time().minute - qr_start_time.minute > 5:
                        return True
                    else:
                        return False
            else:
                return True
    except FileNotFoundError:
        open(".quarantine", 'a').close()
        return False


def logon_page():
    return '''<form method="POST">
            <input name="passwd">
            <input type="submit" text="Log on">
            </form>'''


# Top route needs its own method because subdirs are read from predefinied values and are not necessarily in the same path
def index():
    parent_dirs = ""
    for dir in PARENT_DIR:
        parent_dirs += '<a href={0}><p style="color:red;">{0}</p></div>'.format(dir)
    return parent_dirs


# Listen to password input on login screen
@app.route('/', methods=['POST'])
def post_password():
    passwd_input = request.form['passwd']
    if validate_login(passwd_input):
        return index()
    else:
        return logon_page()


# Return HTML links to subdirectories and files
def render_listing(listing):
    req = request.path
    if req[-1] != "/":
        req += "/"
    # Use different colours for files/directories
    colours = {"file": "blue", "dir": "green"}
    disp = ""
    for item in listing:
        disp += '<a href={1}><p style="color:{0};">{1}</p></div>'.format(colours[item['type']], req + item['name'])
    return disp


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)
