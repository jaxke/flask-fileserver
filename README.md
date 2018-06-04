# Flask-fileserver
Serve files from your filesystem

## Features
* SHA-256 login  
* Configuration file  
* Quarantine mode to prevent "bruteforcing" passwords
* Logging

## Usage
```
$ git clone https://github.com/jaxke/flask-fileserver/
$ cd flask-fileserver  
$ export FLASK_APP=main.py  
$ flask run  
```
Open Firefox at http://0.0.0.0:5000/(if hosted locally) or http://[IP of server]:5000/. Without further configuration it's not
going to reach outside of your local network(if port forwarding is not configured properly).

## Configuration file
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

[Logging]
Enabled: 1
File: serv.log
```

## Logging
Save accesses, downloads and invalid logins by IP address  

```
$ cat serv.log
At Tue Jun  5 01:11:06 2018 by 127.0.0.1 : Navigated to root
At Tue Jun  5 01:11:57 2018 by 127.0.0.1 : Navigated to /home/user/Downloads
At Tue Jun  5 01:12:34 2018 by 127.0.0.1 : Downloaded /home/user/Downloads/textfile.txt
At Wed Jun  6 11:31:22 2018 by 127.0.0.1 : Invalid login
At Wed Jun  6 11:31:22 2018 by 127.0.0.1 : Invalid login
At Wed Jun  6 11:31:23 2018 by 127.0.0.1 : Invalid login
At Wed Jun  6 11:31:23 2018 by 127.0.0.1 : Quarantine invoked
```

## To-do
- [ ] Blacklist to exclude directories and files under definied paths

## Note
This is very early stage and should in no condition be used outside local networks.
