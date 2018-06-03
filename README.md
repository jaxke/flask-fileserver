# Flask-fileserver
Serve files from your filesystem

## Features
* SHA-256 login  
* Configuration file  
* Quarantine mode to prevent "bruteforcing" passwords

### Usage
```
git clone https://github.com/jaxke/flask-fileserver/
cd flask-fileserver  
export FLASK_APP=main.py  
flask run  
```
Open Firefox at http://0.0.0.0:5000/. Without further configuration it's not
going to reach outside of your local network(if port forwarding is not configured properly).

### Configuration file
```
[Security]
# You will need to generate this yourself.(SHA256)
Password: 5e884898da28047151d0e56f8dc6292173623d0d6aab3dd62a11ef721d1542d8
# How many times user can enter a wrong password before locking down
PasswordAttempts: 3
# In minutes
QuarantineTimeout: 5

[Paths]
# Which directories are allowed. Separate with commas. Use absolute paths.
Dirs: /home/user/Downloads,/home/user/Pictures
# To be implemented
Exclude: placeholder
```

## To-do
- [ ] Blacklist to exclude directories and files under definied paths

## Note
This is very early stage and should in no condition be used outside local networks.
