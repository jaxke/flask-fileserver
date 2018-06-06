import os
from pdb import set_trace as st
import hashlib
from flask import Flask, request, abort, jsonify, send_from_directory, send_file, session, render_template
from datetime import datetime, timezone
import configparser
import operator


REAL_PATH = os.path.dirname(os.path.abspath(__file__))
CONF = REAL_PATH + "/config"

app = Flask(__name__)
app.secret_key = "vbju712gg2"


class Config:
    password = ""
    password_attempts = 3
    # This is a runtime value to keep track of failed logins
    curr_attempts = password_attempts
    quarantine_timeout = 5
    allowed_directories = []
    log_file = ""
    def __init__(self):
        Config = configparser.ConfigParser()
        Config.read(CONF)

        self.password = Config.get('Security', 'Password')
        self.password_attempts = int(Config.get('Security', 'PasswordAttempts'))
        self.curr_attempts = self.password_attempts
        self.quarantine_timeout = int(Config.get('Security', 'QuarantineTimeout'))
        self.allowed_directories = Config.get('Paths', 'Dirs').split(",")
        if Config.get('Logging', 'Enabled') == "1":
            self.log_file = Config.get('Logging', 'File')
        else:
            self.log_file = None


# Initialize configuration object
config = Config()

# Expire session variables after 15 minutes(user will have to logon again after this timeout)
@app.before_request
def expire_session():
    from datetime import timedelta
    session.permanent = True
    app.permanent_session_lifetime = timedelta(minutes=15)


def validate_login(passwd_input):
    passwd_input_hash = hashlib.sha256(str.encode(passwd_input))
    passwd_input_hash = passwd_input_hash.hexdigest()
    passwd_valid = config.password
    if passwd_valid == passwd_input_hash:
        session['logged'] = True
    else:
        config.curr_attempts -= 1
        if config.curr_attempts == 0:
            invoke_quarantine()
            return "Quarantine"
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
    # Sort, non case sensitive
    return sorted(files, key=lambda files: files['name'].lower())


# Handle any url below root... works exactly like a file system browser
# This template method is called when a url is loaded that doesn't have a function in this code and the path is stored in 'dir'
@app.route('/<path:dir>')
def fallback(dir):
    # Exclamation == space in url
    dir = dir.replace("!", " ")
    login_check = check_logged()
    # TODO redirect to /login
    if login_check is not True:
        log_access(visitor=request.remote_addr, message="Denied", path=dir)
        return "Forbidden"
    forbidden = True
    # Check if user is trying to access files under pre-specified directories
    for d in config.allowed_directories:
        if ("/"+dir).startswith(d):
            forbidden = False
            break
    if forbidden:
        log_access(visitor=request.remote_addr, message="Denied", path=dir)
        return "Forbidden"
    dir = "/" + dir
    if not os.path.isfile(dir):
        log_access(visitor=request.remote_addr, message="Access", path=dir)
        return render_listing(list_files(dir), dir)
    # User has clicked on a file(as in not a directory), this will enable the browser to popup a download dialog for that file
    else:
        log_access(visitor=request.remote_addr, message="Download", path=dir)
        return send_file(dir, as_attachment=True, attachment_filename=dir.split("/")[-1])


@app.route('/')
# Top route needs its own method because subdirs are read from predefinied values and are not necessarily in the same path
def index():
    log_access(visitor=request.remote_addr, message="Access", path="root")
    login_check = check_logged()
    if login_check is False:
        log_access(visitor=request.remote_addr, message="invalid login", path="root")
        return logon_page()
    elif login_check == True:
        parents = []
        for dir in config.allowed_directories:
            parents.append({"name": dir, "type": "dir"})
        return render_listing(parents, "root")
    elif login_check == "Quarantine":
        return user_in_quarantine()

@app.route('/settings')
def settings():
    pass


@app.route('/logout')
def logout():
    log_access(visitor=request.remote_addr, message="logout", path=None)
    session.clear()
    return index()


def check_logged():
    if not check_quarantine():
        return user_in_quarantine()
    if session.get('logged', False):
        return True
    else:
        return False


def invoke_quarantine():
    log_access(visitor=request.remote_addr, message="quarantine", path=None)
    # Reset "current attempts" to default upon invoking quarantine
    config.curr_attempts = config.password_attempts
    # Create file(or recreate silently)
    open(".quarantine", 'a').close()
    with open(".quarantine", "w") as qw:
        qw.write(datetime.now().strftime("%Y/%m/%d %H:%M:%S"))


def user_in_quarantine():
    return "<p> You are in quarantine. You may try to login soon again. </p>"


# Very lazy method for checking if x mins has passed, will not work when hour changes.
# Return False if in quarantine, True if not
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
                    if datetime.now().time().minute - qr_start_time.minute > config.quarantine_timeout:
                        return True
                    else:
                        return False
            else:
                return True
    except FileNotFoundError:
        return True


def logon_page():
    return render_template('logon.html')


# TODO Method only works in /, logout redirects to /logout => does not work there
# Listen to password input on login screen
@app.route('/', methods=['POST'])
def post_password():
    passwd_input = request.form['passwd']
    login_validation = validate_login(passwd_input)
    if login_validation == True:
        return index()
    elif login_validation == "Quarantine":
        return user_in_quarantine()
    else:
        return logon_page()


# Return HTML links to subdirectories and files
def render_listing(listing, dir):
    # Top title of page
    title = dir
    # List of dicts(files/dirs)
    entries = []
    # No need for step back in the top page
    if dir != "root":
        # No need for (..) in top directories because upper dirs are forbidden
        if dir not in config.allowed_directories:
            parent_dir = "/".join(dir.split("/")[0:-1])
            entries.append({"href": parent_dir, "type": "step_back", "value": ".."})
        dir = dir + "/"
    # Avoid double slash
    else:
        dir = ""
    for item in listing:
        # Avoid spaces in url, Ie. "/home/user/this\ is\ file" => "/home/user/this!is!file" for url
        item_nospace = dir + item['name'].replace(" ", "!")
        # ... and display a's values with spaces instead of exclamation marks, and without full path
        item_proper_name = (item['name']).replace("!", " ")
        if item['type'] == "dir":
            item_proper_name += "/"
        # Type == class in Jinja(listing.html)
        entries.append({"href": item_nospace, "type": item['type'], "value": item_proper_name})
    return render_template('listing.html', **locals())


# This method writes to log file.
# Visitor = IP Address of computer that invoked this function, path = where(url) this function was called
def log_access(visitor, message, path):
    if config.log_file == None:
        return
    with open(config.log_file, "a+") as log:
        # TODO proper date format DD/MM/YYYY
        log.write("At {0} by {1} : ".format(datetime.now().ctime(), visitor, path))
        if message == "Denied":
            log.write("Access denied")
        elif message == "invalid login":
            log.write("Invalid login")
        elif message == "quarantine":
            log.write("Quarantine invoked")
        elif message == "Download":
            log.write("Downloaded " + path)
        elif message == "Access":
            log.write("Navigated to " + path)
        elif message == "logout":
            log.write("Logged out.")
        log.write("\n")


if __name__ == '__main__':
    app.run(host="0.0.0.0", port=5000)
