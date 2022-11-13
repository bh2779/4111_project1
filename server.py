import os
from sqlalchemy import *
from sqlalchemy.pool import NullPool
from flask import Flask, request, render_template, g, redirect, Response, flash
import random
import string
from datetime import date, datetime

tmpl_dir = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'templates')
app = Flask(__name__, template_folder=tmpl_dir)

DB_USER = "bh2779"
DB_PASSWORD = "databases2022"

DB_SERVER = "w4111project1part2db.cisxo09blonu.us-east-1.rds.amazonaws.com"

DATABASEURI = "postgresql://"+DB_USER+":"+DB_PASSWORD+"@"+DB_SERVER+"/proj1part2"

engine = create_engine(DATABASEURI)

"""
Accepted characters for validation:
A-Z
a-z
0-9
-
" "
"""


# takes in a string and checks if the characters are valid
def name_val(name):
    for letter in name:
        if letter not in string.ascii_letters + " " + "-":
            return False, "Invalid characters in input. Please only use upper or lowercase letters, space, or -."
    return True, "OK"


# takes in a string of integers and confirms they are a valid day entry
def day_val(val):
    # check length of input
    if len(val) == 0 or len(val) > 2:
        return False, "Please enter a valid number between 01-31."
    # check if all characters are valid digits
    for ch in val:
        if ch not in string.digits:
            return False, "Please enter a valid number between 01-31."
    # check range
    if int(val) < 1 or int(val) > 31:
        return False, "Please enter a valid number between 01-31."
    # if length 1, add 0 to front
    if len(val) == 1:
        return True, "0" + val
    return True, val


# takes in a string of integers and confirms they are a valid month entry
def month_val(val):
    # check length of input
    if len(val) == 0 or len(val) > 2:
        return False, "Please enter a valid number between 01-12."
    # check if all characters are valid digits
    for ch in val:
        if ch not in string.digits:
            return False, "Please enter a valid number between 01-12."
    # check range
    if int(val) < 1 or int(val) > 12:
        return False, "Please enter a valid number between 01-12."
    # if length 1, add 0 to front
    if len(val) == 1:
        return True, "0" + val
    return True, val


def year_val(val):
    year = date.today().year
    # check length of input
    if len(val) != 4:
        return False, f"Please enter a valid 4 digit number between 1900 and {year}."
    # check if all characters are valid digits
    for ch in val:
        if ch not in string.digits:
            return False, f"Please enter a valid 4 digit number between 1900 and {year}."
    # check range
    if int(val) < 1900 or int(val) > year:
        return False, f"Please enter a valid 4 digit number between 1900 and {year}."
    return True, "OK"


# takes in year, month, day and confirms it is a valid date via the datetime library
# probably could have been used to sanity check input too, but oh well ¯\_(ツ)_/¯
def full_date_val(year, month, day):
    valid_date = None
    try:
        input_date = datetime(year=int(year), month=int(month), day=int(day))
        if input_date.year < 2000:
            valid_date = False
        else:
            valid_date = True
    except ValueError:
        valid_date = False
    if valid_date == False:
        return False, "Date is not valid."
    else:
        return True, "OK"


# takes in location and confirms all characters are valid
def location_val(val):
    for ch in val:
        if ch not in (string.ascii_letters + string.digits + " " + "-"):
            return False, "Invalid characters entered."

    return True, "OK"


# takes in name of software and confirms all characters are valid
def software_val(val):
    for ch in val:
        if ch not in (string.ascii_letters + string.digits + "-"):
            return False, "Invalid characters entered."

    return True, "OK"


# takes in software version and confirms all characters are valid
def version_val(val):
    for ch in val:
        if ch not in (string.ascii_letters + string.digits + "."):
            return False, "Invalid characters entered."

    return True, "OK"


def created_by_val(val):
    for ch in val:
        if ch not in (string.ascii_letters + string.digits + " " + "-"):
            return False, "Invalid characters entered."
    return True, "OK"


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
    # populate user names on main page
    cursor = g.conn.execute("SELECT user_id, first_name, last_name FROM users")
    names = []
    for result in cursor:
        names.append([result['user_id'], result['first_name'] + ' ' + result['last_name']])
    cursor.close()
    context = dict(data = names)
    return render_template("index.html", **context)


@app.route('/add-profile', methods=['POST'])
def add_profile():
    # user inputs and validation
    first_name = request.form['first_name']
    if not name_val(first_name)[0]:
        return redirect('/')
    last_name = request.form['last_name']
    if not name_val(last_name)[0]:
        return redirect('/')
    dob = request.form['dob']

    try:
        year, month, day = dob.split('-')
    except:
        return redirect('/')
    if not year_val(year)[0]:
        return redirect('/')
    # expanding these since the function fixes single value entries
    month_status, month = month_val(month)
    if not month_status:
        return redirect('/')
    day_status, day = day_val(day)
    if not day_status:
        return redirect('/')
    try:
        dob_datetime = datetime(year=int(year), month=int(month), day=int(day))
        if dob_datetime > datetime.today() or dob_datetime < datetime(year=1900, month=1, day=1):
            return redirect('/')
    except:
        return redirect('/')

    location = request.form['location']
    if not location_val(location)[0]:
        return redirect('/')
    dept = request.form['dept']
    if dept not in ['Sales', 'HR', 'IT']:
        return redirect('/')
    role = request.form['role']
    all_roles = []
    cursor = g.conn.execute('SELECT role_name FROM role')
    for result in cursor:
        all_roles.append(result['role_name'])
    cursor.close()
    if role not in all_roles:
        return redirect('/')

    created_by = request.form['created_by']
    if not created_by_val(created_by)[0]:
        return redirect('/')

    # insert new user into database
    cmd = 'INSERT INTO users(first_name, last_name, dob, location, department) VALUES (:first_name, :last_name, :dob, :location, :dept)'
    g.conn.execute(text(cmd), first_name = first_name, last_name = last_name, dob = dob, location = location, dept = dept)
    # generate new account information for users
    cursor = g.conn.execute('SELECT user_id FROM users WHERE first_name LIKE %s AND last_name LIKE %s', [first_name, last_name])
    userid = 0
    for result in cursor:
        userid = result['user_id']
    username = first_name[0].lower() + last_name[0].lower() + str(random.randrange(0,999))
    email = username + '@company.com'
    letters = string.ascii_letters
    password = ''.join(random.choice(letters) for i in range(8))
    created_date = date.today()
    # insert into account table
    cmd = 'INSERT INTO account(email, password, username, created_date, user_id) VALUES (:email, :password, :username, :created_date, :user_id)'
    g.conn.execute(text(cmd), email = email, password = password, username = username, created_date = created_date, user_id = userid)
    cursor = g.conn.execute('SELECT account_id FROM account WHERE user_id = %s', str(userid))
    accountid = 0
    for result in cursor:
        accountid = result['account_id']
    # insert into assigned
    cmd = 'INSERT INTO assigned(account_id, user_id, created_by) VALUES (:account_id, :user_id, :created_by)'
    g.conn.execute(text(cmd), account_id = accountid, user_id = userid, created_by = created_by)
    cursor = g.conn.execute('SELECT role_id FROM role WHERE role_name LIKE %s', role)
    roleid = 0
    for result in cursor:
        roleid = result['role_id']
    # insert into belongs_to
    cmd = 'INSERT INTO belongs_to(account_id, role_id, last_reviewed) VALUES (:account_id, :role_id, :last_reviewed)'
    g.conn.execute(text(cmd), account_id = accountid, role_id = roleid, last_reviewed = created_date)
    cursor.close()
    return redirect('/')


#displays individual users's information
@app.route('/profile/<int:userid>')
def profile(userid):
    cursor = g.conn.execute("SELECT * FROM users WHERE user_id = " + str(userid))
    user_info = []
    for result in cursor:
        user_info.append(result['user_id'])
        user_info.append(result['first_name'] + ' ' + result['last_name'])
        user_info.append(result['location'])
        user_info.append(result['department'])
    cursor = g.conn.execute("SELECT account_id, username, email FROM account WHERE user_id = %s", str(userid))
    accounts = []
    for result in cursor:
        accounts.append([result['account_id'], result['username'], result['email']])
    user_info.append(accounts)
    for account in user_info[4]:
        account_id = account[0]
        cursor = g.conn.execute("SELECT R.role_id, role_name, last_reviewed FROM role AS R JOIN belongs_to AS B ON R.role_id = B.role_id WHERE account_id = %s", str(account_id))
        role_id = 0
        for result in cursor:
            role_id = result['role_id']
            account.append(result['role_name'] + ' (last reviewed on ' + str(result['last_reviewed']) + ')')
        cursor = g.conn.execute("SELECT created_by FROM assigned WHERE user_id = %s", str(userid))
        created_by = ""
        for result in cursor:
            created_by = result['created_by']
        account.append(created_by)
        cursor = g.conn.execute("SELECT rule FROM determines_permissions WHERE role_id = %s", str(role_id))
        access = False
        for result in cursor:
            if result['rule'] == 'confidential info access':
                access = True
                break
        if access:
            account.append('True')
        else:
            account.append('False')
        cursor = g.conn.execute("SELECT name, duration FROM software AS S JOIN authorized AS A ON S.sid = A.sid WHERE account_id = %s", str(account_id))
        softwares = []
        for result in cursor:
            softwares.append(result['name'] + ' (authorized until ' + str(result['duration']) + ')')
        account.append(softwares)
    cursor.close()
    print(user_info)
    context = dict(data = user_info)
    return render_template("profile.html", **context)


# used to add a new account
@app.route('/account/<int:user_id>/add', methods=['POST'])
def add_account(user_id):
    role = request.form['role']
    all_roles = []
    cursor = g.conn.execute('SELECT role_name FROM role')
    for result in cursor:
        all_roles.append(result['role_name'])
    cursor.close()
    if role not in all_roles:
        return redirect('/')
    created_by = request.form['created_by']
    if not created_by_val(created_by)[0]:
        return redirect('/account/<int:user_id>/add')
    created_date = date.today()
    cursor = g.conn.execute("SELECT first_name, last_name FROM users WHERE user_id = %s", str(user_id))
    first_name = ''
    last_name = ''
    for result in cursor:
        first_name = result['first_name']
        last_name = result['last_name']
    username = first_name[0].lower() + last_name[0].lower() + str(random.randrange(0,999))
    email = username + '@company.com'
    letters = string.ascii_letters
    password = ''.join(random.choice(letters) for i in range(8))
    cmd = 'INSERT INTO account(email, password, username, created_date, user_id) VALUES (:email, :password, :username, :created_date, :user_id)'
    g.conn.execute(text(cmd), email = email, password = password, username = username, created_date = created_date, user_id = user_id)
    cursor = g.conn.execute("SELECT role_id FROM role WHERE role_name LIKE '" + role + "'")
    role_id = 0
    for result in cursor:
        role_id = result['role_id']
    cursor = g.conn.execute('SELECT account_id FROM account WHERE user_id = %s AND username LIKE %s AND password LIKE %s', [str(user_id), username, password])
    account_id = 0
    for result in cursor:
        account_id = result['account_id']
    cmd = 'INSERT INTO belongs_to(account_id, role_id, last_reviewed) VALUES (:account_id, :role_id, :last_reviewed)'
    g.conn.execute(text(cmd), account_id = account_id, role_id = role_id, last_reviewed = created_date)
    cmd = 'INSERT INTO assigned(account_id, user_id, created_by) VALUES (:account_id, :user_id, :created_by)'
    g.conn.execute(text(cmd), account_id = account_id, user_id = user_id, created_by = created_by)
    cursor.close()
    return profile(user_id)

@app.route('/account/<int:account_id>/delete', methods=['POST'])
def delete_account(account_id):
    cursor = g.conn.execute("SELECT user_id FROM account WHERE account_id = %s", str(account_id))
    user_id = 0
    for result in cursor:
        user_id = result['user_id']
    g.conn.execute("DELETE FROM belongs_to WHERE account_id = %s", str(account_id))
    g.conn.execute("DELETE FROM accesses WHERE account_id = %s", str(account_id))
    g.conn.execute("DELETE FROM assigned WHERE account_id = %s", str(account_id))
    g.conn.execute("DELETE FROM authorized WHERE account_id = %s", str(account_id))
    g.conn.execute("DELETE FROM account WHERE account_id = %s", str(account_id))
    return profile(user_id)

@app.route('/user/<int:user_id>/delete', methods=['POST'])
def delete_user(user_id):
    account_ids = []
    cursor = g.conn.execute("SELECT account_id FROM account WHERE user_id = %s", str(user_id))
    for result in cursor:
        account_ids.append(result['account_id'])
    for account_id in account_ids:
        g.conn.execute("DELETE FROM belongs_to WHERE account_id = %s", str(account_id))
        g.conn.execute("DELETE FROM accesses WHERE account_id = %s", str(account_id))
        g.conn.execute("DELETE FROM assigned WHERE account_id = %s", str(account_id))
        g.conn.execute("DELETE FROM authorized WHERE account_id = %s", str(account_id))
        g.conn.execute("DELETE FROM account WHERE account_id = %s", str(account_id))
    g.conn.execute("DELETE FROM account WHERE user_id = %s", str(user_id))
    g.conn.execute("DELETE FROM users WHERE user_id = %s", str(user_id))
    return redirect('/')

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
    cursor = g.conn.execute("SELECT * FROM device WHERE device_id = %s", str(deviceid))
    device_info = []
    for result in cursor:
        device_info.append(result['device_id'])
        device_info.append(result['vendor'] + ' ' + result['device_type'])
        device_info.append(result['operating_system'])
        device_info.append(result['bios_version'])
    cursor = g.conn.execute("SELECT scope, groups FROM defines AS D JOIN device_permissions AS P ON D.device_permissions_id = P.device_permissions_id WHERE device_id = %s", str(deviceid))
    for result in cursor:
        device_info.append(result['scope'])
        device_info.append(result['groups'])
    cursor = g.conn.execute("SELECT account_id, login_timestamp FROM accesses AS A JOIN session AS S ON A.session_id = S.session_id WHERE device_id = %s", str(deviceid))
    timestamps = []
    for result in cursor:
        timestamps.append([result['login_timestamp'], result['account_id']])
    if len(timestamps) > 0:
        timestamps.sort()
        cursor = g.conn.execute("SELECT username FROM account WHERE account_id = %s", str(timestamps[-1][1]))
        username = ""
        for result in cursor:
            username = result['username']
        device_info.append(str(timestamps[-1][0]) + ' by ' + username)
    else:
        device_info.append("Never accessed")
    cursor.close()
    context = dict(data = device_info)
    return render_template("device.html", **context)

@app.route('/add-device', methods=['POST'])
def add_device():
    device_type = request.form['device_type']
    operating_system = request.form['operating_system']
    purchase_date = request.form['purchase_date']
    bios_version = request.form['bios_version']
    vendor = request.form['vendor']
    scope = request.form['scope']
    groups = request.form['groups']
    if not name_val(vendor)[0]:
        return redirect('/devices')
    if not software_val(bios_version)[0]:
        return redirect('/devices')
    try:
        year, month, day = purchase_date.split('-')
    except:
        return redirect('/devices')
    if not year_val(year)[0]:
        return redirect('/devices')
    # expanding these since the function fixes single value entries
    month_status, month = month_val(month)
    if not month_status:
        return redirect('/devices')
    day_status, day = day_val(day)
    if not day_status:
        return redirect('/devices')
    purchase_datetime = datetime(year=int(year), month=int(month), day=int(day))
    if purchase_datetime > datetime.today() or purchase_datetime < datetime(year=1900, month=1, day=1):
        return redirect('/devices')
    cursor = g.conn.execute("SELECT device_permissions_id FROM device_permissions WHERE scope LIKE %s AND groups LIKE %s", [scope, groups])
    device_permissions_id = -1
    for result in cursor:
        device_permissions_id = result['device_permissions_id']
    if device_permissions_id == -1:
        return redirect('/devices')
    cmd = 'INSERT INTO device(device_type, purchase_date, operating_system, bios_version, vendor) VALUES (:device_type, :purchase_date, :operating_system, :bios_version, :vendor)'
    g.conn.execute(text(cmd), device_type = device_type, purchase_date = purchase_date, operating_system = operating_system, bios_version = bios_version, vendor = vendor)
    cursor = g.conn.execute("SELECT device_id FROM device WHERE bios_version LIKE %s", bios_version)
    device_id = -1
    for result in cursor:
        device_id = result['device_id']
    cmd = 'INSERT INTO defines(device_id, device_permissions_id) VALUES (:device_id, :device_permissions_id)'
    g.conn.execute(text(cmd), device_id = device_id, device_permissions_id = device_permissions_id)
    return redirect('/devices')

@app.route('/device/<int:device_id>/delete', methods=['POST'])
def delete_device(device_id):
    g.conn.execute("DELETE FROM accesses WHERE device_id = %s", str(device_id))
    g.conn.execute("DELETE FROM defines WHERE device_id = %s", str(device_id))
    g.conn.execute("DELETE FROM accesses WHERE device_id = %s", str(device_id))
    g.conn.execute("DELETE FROM device WHERE device_id = %s", str(device_id))
    return redirect('/devices')

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
    cursor = g.conn.execute("SELECT * FROM software WHERE sid = %s", str(sid))
    software_info = [sid]
    for result in cursor:
        software_info.append(result['name'])
        software_info.append(result['version'])
        software_info.append(result['license'])
        software_info.append(result['renew_date'])
    cursor.close()
    context = dict(data = software_info)
    return render_template("software.html", **context)

@app.route('/add-software', methods=['POST'])
def add_software():
    name = request.form['name']
    if not software_val(name)[0]:
        return redirect('/softwares')
    version = request.form['version']
    if not version_val(version)[0]:
        return redirect('/softwares')
    license = request.form['license']
    if not name_val(license)[0]:
        return redirect('/softwares')
    renew_date = request.form['renew_date']
    try:
        year, month, day = renew_date.split('-')
    except:
        return redirect('/softwares')
    if not full_date_val(year, month, day)[0]:
        return redirect('/softwares')
    cmd = 'INSERT INTO software(name, version, license, renew_date) VALUES (:name, :version, :license, :renew_date)'
    g.conn.execute(text(cmd), name = name, version = version, license = license, renew_date = renew_date)
    return redirect('/softwares')

@app.route('/software/<int:sid>/delete', methods=['POST'])
def delete_software(sid):
    g.conn.execute("DELETE FROM authorized WHERE sid = %s", str(sid))
    g.conn.execute("DELETE FROM software WHERE sid = %s", str(sid))
    return redirect('/softwares')

@app.route('/roles')
def roles():
    cursor = g.conn.execute("SELECT role_id, role_name FROM role")
    roles = []
    for result in cursor:
        roles.append([result['role_id'], result['role_name']])
    cursor.close()
    context = dict(data = roles)
    return render_template("roles.html", **context)

@app.route('/role/<int:role_id>')
def role(role_id):
    role_info = []
    cursor = g.conn.execute("SELECT role_name FROM role WHERE role_id = %s", str(role_id))
    for result in cursor:
        role_info.append(result['role_name'])
    permissions = []
    cursor = g.conn.execute("SELECT rule FROM determines_permissions WHERE role_id = %s", str(role_id))
    for result in cursor:
        permissions.append(result['rule'])
    role_info.append(permissions)
    cursor.close()
    context = dict(data = role_info)
    return render_template("role.html", **context)

@app.route('/device-permissions')
def device_permissions():
    cursor = g.conn.execute("SELECT scope, groups FROM device_permissions")
    dp = []
    for result in cursor:
        dp.append('Scope: ' + result['scope'] + ', Groups: ' + result['groups'])
    cursor.close()
    context = dict(data = dp)
    return render_template("device_permissions.html", **context)

@app.route('/role-permissions')
def role_permissions():
    cursor = g.conn.execute("SELECT DISTINCT rule FROM determines_permissions")
    rp = []
    for result in cursor:
        rp.append('Rule: ' + result['rule'])
    cursor.close()
    context = dict(data = rp)
    return render_template("role_permissions.html", **context)


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