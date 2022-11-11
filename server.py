import os
from sqlalchemy import *
from sqlalchemy.pool import NullPool
from flask import Flask, request, render_template, g, redirect, Response
import random
import string
from datetime import date

tmpl_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
app = Flask(__name__, template_folder=tmpl_dir)

DB_USER = "bh2779"
DB_PASSWORD = "databases2022"

DB_SERVER = "w4111project1part2db.cisxo09blonu.us-east-1.rds.amazonaws.com"

DATABASEURI = "postgresql://"+DB_USER+":"+DB_PASSWORD+"@"+DB_SERVER+"/proj1part2"

engine = create_engine(DATABASEURI)

@app.before_request
def before_request():
    try:
        g.conn = engine.connect()
    except:
        print("uh oh, problem connecting to database")
        import traceback; traceback.print_exc()
        g.conn = None

@app.teardown_request
def teardown_request(exception):
    try:
        g.conn.close()
    except Exception as e:
        pass

@app.route('/')
def index():
    cursor = g.conn.execute("SELECT user_id, first_name, last_name FROM users")
    names = []
    for result in cursor:
        names.append([result['user_id'], result['first_name'] + ' ' + result['last_name']])
    cursor.close()
    context = dict(data = names)
    return render_template("index.html", **context)

@app.route('/add-profile', methods=['POST'])
def add_profile():
    first_name = request.form['first_name']
    last_name = request.form['last_name']
    dob = request.form['dob']
    location = request.form['location']
    dept = request.form['dept']
    role = request.form['role']
    all_roles = []
    cursor = g.conn.execute('SELECT role_name FROM role')
    for result in cursor:
        all_roles.append(result['role_name'])
    cursor.close()
    if role not in all_roles:
        return redirect('/')
    created_by = request.form['created_by']
    cmd = 'INSERT INTO users(first_name, last_name, dob, location, department) VALUES (:first_name, :last_name, :dob, :location, :dept)'
    g.conn.execute(text(cmd), first_name = first_name, last_name = last_name, dob = dob, location = location, dept = dept)
    cmd = 'SELECT user_id FROM users WHERE first_name LIKE \'' + first_name + '\' AND last_name LIKE \'' + last_name + '\''
    cursor = g.conn.execute(cmd)
    userid = 0
    for result in cursor:
        userid = result['user_id']
    username = first_name[0].lower() + last_name[0].lower() + str(random.randrange(0,999))
    email = username + '@company.com'
    letters = string.ascii_letters
    password = ''.join(random.choice(letters) for i in range(8))
    created_date = date.today()
    cmd = 'INSERT INTO account(email, password, username, created_date, user_id) VALUES (:email, :password, :username, :created_date, :user_id)'
    g.conn.execute(text(cmd), email = email, password = password, username = username, created_date = created_date, user_id = userid)
    cmd = 'SELECT account_id FROM account WHERE user_id = ' + str(userid)
    cursor = g.conn.execute(cmd)
    accountid = 0
    for result in cursor:
        accountid = result['account_id']
    cmd = 'INSERT INTO assigned(account_id, user_id, created_by) VALUES (:account_id, :user_id, :created_by)'
    g.conn.execute(text(cmd), account_id = accountid, user_id = userid, created_by = created_by)
    cursor = g.conn.execute('SELECT role_id FROM role WHERE role_name LIKE \'' + role + '\'')
    roleid = 0
    for result in cursor:
        roleid = result['role_id']
    cmd = 'INSERT INTO belongs_to(account_id, role_id, last_reviewed) VALUES (:account_id, :role_id, :last_reviewed)'
    g.conn.execute(text(cmd), account_id = accountid, role_id = roleid, last_reviewed = created_date)
    cursor.close()
    return redirect('/')

@app.route('/profile/<int:userid>')
def profile(userid):
    cursor = g.conn.execute("SELECT * FROM users WHERE user_id = " + str(userid))
    user_info = []
    for result in cursor:
        user_info.append(result['first_name'] + ' ' + result['last_name'])
        user_info.append(result['location'])
        user_info.append(result['department'])
    cursor = g.conn.execute("SELECT account_id, email FROM account WHERE user_id = " + str(userid))
    account_id = 0
    for result in cursor:
        account_id = result['account_id']
        user_info.append(result['email'])
    cursor = g.conn.execute("SELECT R.role_id, role_name FROM role AS R JOIN belongs_to AS B ON R.role_id = B.role_id WHERE account_id = " + str(account_id))
    role_id = 0
    for result in cursor:
        role_id = result['role_id']
        user_info.append(result['role_name'])
    cursor = g.conn.execute("SELECT created_by FROM assigned WHERE user_id = " + str(userid))
    for result in cursor:
        user_info.append(result['created_by'])
    cursor = g.conn.execute("SELECT rule FROM determines_permissions WHERE role_id = " + str(role_id))
    access = False
    for result in cursor:
        if result['rule'] == 'confidential info':
            access = True
            break
    if access:
        user_info.append('True')
    else:
        user_info.append('False')
    cursor = g.conn.execute("SELECT name, duration FROM software AS S JOIN authorized AS A ON S.sid = A.sid WHERE account_id = " + str(account_id))
    softwares = []
    for result in cursor:
        softwares.append(result['name'] + ' (authorized until ' + str(result['duration']) + ')')
    user_info.append(softwares)
    cursor.close()
    print(user_info)
    context = dict(data = user_info)
    return render_template("profile.html", **context)

@app.route('/devices')
def devices():
    cursor = g.conn.execute("SELECT device_id, device_type, vendor FROM device")
    devices = []
    for result in cursor:
        devices.append([result['device_id'], result['vendor'] + ' ' + result['device_type']])
    cursor.close()
    context = dict(data = devices)
    return render_template("devices.html", **context)

@app.route('/device/<int:deviceid>')
def device(deviceid):
    cursor = g.conn.execute("SELECT * FROM device WHERE device_id = " + str(deviceid))
    device_info = []
    for result in cursor:
        device_info.append(result['vendor'] + ' ' + result['device_type'])
        device_info.append(result['operating_system'])
        device_info.append(result['bios_version'])
    cursor = g.conn.execute("SELECT scope, groups FROM defines AS D JOIN device_permissions AS P ON D.device_permissions_id = P.device_permissions_id WHERE device_id = " + str(deviceid))
    for result in cursor:
        device_info.append(result['scope'])
        device_info.append(result['groups'])
    cursor = g.conn.execute("SELECT account_id, login_timestamp FROM accesses AS A JOIN session AS S ON A.session_id = S.session_id WHERE device_id = " + str(deviceid))
    timestamps = []
    for result in cursor:
        timestamps.append([result['login_timestamp'], result['account_id']])
    if len(timestamps) > 0:
        timestamps.sort()
        cursor = g.conn.execute("SELECT username FROM account WHERE account_id = " + str(timestamps[-1][1]))
        username = ""
        for result in cursor:
            username = result['username']
        device_info.append(str(timestamps[-1][0]) + ' by ' + username)
    else:
        device_info.append("Never accessed")
    cursor.close()
    context = dict(data = device_info)
    return render_template("device.html", **context)

@app.route('/softwares')
def softwares():
    cursor = g.conn.execute("SELECT sid, name FROM software")
    softwares = []
    for result in cursor:
        softwares.append([result['sid'], result['name']])
    cursor.close()
    context = dict(data = softwares)
    return render_template("softwares.html", **context)

@app.route('/software/<int:sid>')
def software(sid):
    cursor = g.conn.execute("SELECT * FROM software WHERE sid = " + str(sid))
    software_info = []
    for result in cursor:
        software_info.append(result['name'])
        software_info.append(result['version'])
        software_info.append(result['license'])
        software_info.append(result['renew_date'])
    cursor.close()
    context = dict(data = software_info)
    return render_template("software.html", **context)

if __name__ == "__main__":
    import click

    @click.command()
    @click.option('--debug', is_flag=True)
    @click.option('--threaded', is_flag=True)
    @click.argument('HOST', default='0.0.0.0')
    @click.argument('PORT', default=8111, type=int)
    
    def run(debug, threaded, host, port):
        HOST, PORT = host, port
        app.run(host=HOST, port=PORT, debug=debug, threaded=threaded)

    run()
