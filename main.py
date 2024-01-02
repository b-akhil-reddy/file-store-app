import os, secrets
import hashlib
import re
from google.cloud import storage
from flask import Flask, render_template, request, redirect,send_file, jsonify, session
from google.oauth2 import service_account
from dotenv import load_dotenv
import json
from functools import wraps

from sqlalchemy import create_engine, Column, Integer, String, ForeignKey, Text, Boolean
from sqlalchemy.orm import sessionmaker, declarative_base


from PIL import Image, ExifTags
from PIL.ExifTags import TAGS

# from google.cloud import firestore

# db = firestore.Client()

if not os.path.exists("./files/"):
    os.mkdir("./files/")

load_dotenv("./.env")

app = Flask(__name__)
app.secret_key = os.environ["SECRET_KEY"]
engine = create_engine(os.environ["DB_URI"])

Base = declarative_base()
class User(Base):
    __tablename__ = 'users'

    userid = Column(String(32), primary_key=True, unique=True, nullable=False)
    uname = Column(String(100), nullable=False, unique=True)
    passwd = Column(Text, nullable=False)
    email = Column(String(254), nullable=False, unique=True)
    salt = Column(Text, nullable=False)
    phone = Column(Text, nullable=False)

class Metadata(Base):
    __tablename__ = 'metadata'

    filename = Column(Text, nullable=False)
    fileid = Column(String(32), primary_key=True, unique=True, nullable=False)
    bucket = Column(Text, nullable=False)
    loc_in_bucket = Column(Text, nullable=False)
    image_size = Column(Text, nullable=False)
    image_height = Column(Integer, nullable=False)
    image_width = Column(Integer, nullable=False)
    image_format = Column(Text, nullable=False)
    image_mode = Column(Text, nullable=False)
    image_is_animated = Column(Boolean, nullable=False)
    frames_in_image = Column(Integer, nullable=False)
    exif_data_available = Column(Boolean, nullable=False)
    exif_data = Column(Text)
    userid = Column(ForeignKey(User.userid), nullable=False)

# Base.metadata.drop_all(engine)

Base.metadata.create_all(engine)

db_session = None
@app.before_request
def startup_session():
    global db_session
    db_session = sessionmaker(bind=engine)
    db_session = db_session()

@app.teardown_request
def shutdown_session(exception=None): 
    db_session.close_all()

key_file_path = os.environ["GOOGLE_APPLICATION_CREDENTIALS"]
credentials = service_account.Credentials.from_service_account_file(key_file_path)
storage_client = storage.Client(credentials.project_id)
bucket_name = os.environ["BUCKET_NAME"]
bucket = storage_client.bucket(bucket_name)

def requires_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('uname') == None or session.get('userid') == None:
            return redirect("/?error=You need to Sign-in first")
        else:
            request.user = db_session.query(User).filter_by(uname=session["uname"],userid=session["userid"]).first()
            if(request.user==None):
                session.clear()
                return redirect("/?error=You need to Sign-in first")
        return f(*args, **kwargs)
    return decorated

def already_auth(f):
    @wraps(f)
    def decorated(*args, **kwargs):
        if session.get('uname') != None and session.get('userid') != None:
            return redirect("/user?error=You need to Sign-out first")
        return f(*args, **kwargs)
    return decorated

@app.route('/', methods=['GET', 'POST'])
@app.route('/home', methods=['GET', 'POST'])
@app.route('/index', methods=['GET', 'POST'])
@app.route('/signin', methods=['GET', 'POST'])
@already_auth
def signin():
    if request.method == 'POST':
        uname = request.form['uname']
        passwd = request.form['passwd']
        user = db_session.query(User).filter_by(uname=uname).first()
        if user == None:
            return jsonify({"uname": "Invalid Username or Password", "passwd": "Invalid Username or Password"})
        else:
            hash = str(hashlib.sha256((passwd+user.salt).encode()).hexdigest())
            if user:
                if user.passwd == hash:
                    session['uname'] = user.uname
                    session['userid'] = user.userid
                    return jsonify({"message": "Successfully Signed-in"})
                else:
                    return jsonify({"uname": "Invalid Username or Password", "passwd": "Invalid Username or Password"})
            else:
                return jsonify({"uname": "Invalid Username or Password", "passwd": "Invalid Username or Password"})
    elif request.method == 'GET':
        return render_template('signin.html')

def validatePassword(passwd):
    if(len(passwd)<8):
        return False,"Password must be atleast 8 characters long"
    elif(not any(char.isdigit() for char in passwd)):
        return False,"Password must have atleast one digit"
    elif(not any(char.isupper() for char in passwd)):
        return False,"Password must have atleast one uppercase character"
    elif(not any(char.islower() for char in passwd)):
        return False,"Password must have atleast one lowercase character"
    elif(re.match(r"^(?=.*[a-z])(?=.*[A-Z])(?=.*\d)(?=.*[@$!%*?&])[A-Za-z\d@$!%*?&]{8,}$",passwd)==None):
        return False,"Password must have atleast one special character"
    return True,""

@app.route('/signup', methods=['GET', 'POST'])
@already_auth
def signup():
    if request.method == "POST":
        if all(elem not in request.form.keys() for elem in ["uname","passwd","cpasswd","email","phone"]):
            return jsonify({"message":"Incomplete form"})
        uname = request.form['uname']
        err = {}
        user = db_session.query(User).filter_by(uname=uname).first()
        if user:
            err["uname"] = 'Username already used'
        passwd = request.form['passwd']
        cpasswd = request.form['cpasswd']
        test = validatePassword(passwd)
        if not test[0]:
            err["passwd"] = test[1]
        if passwd != cpasswd:
            err["cpasswd"] = 'Passwords do not match'
        email = request.form['email']
        if not re.match(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",email):
            err["email"]='Invalid Email address'
        elif db_session.query(User).filter_by(email=email).first():
            err["email"]='Email already used'
        phone = request.form['phone']
        if not phone.isdigit():
            err["phone"]='Phone Number must be digits only'
        elif len(phone)!=10:
            err["phone"]='Phone Number must be 10 digits long'
        elif db_session.query(User).filter_by(phone=phone).first():
            err["phone"]='Phone Number already used'
        if err:
            return jsonify(err)
        salt = str(secrets.token_hex(16))
        hash = str(hashlib.sha256((passwd+salt).encode('utf-8')).hexdigest())
        user = User(
            userid=str(secrets.token_hex(16)),
            uname=uname,
            passwd=hash,
            email=email,
            salt=salt,
            phone=phone
        )
        db_session.add(user)
        db_session.commit()
        return jsonify({"message":"Successfully created user, You can now Sign-in to your account"})
    elif request.method == "GET":
        return render_template('signup.html')

@app.route('/user')
@requires_auth
def user():
    return render_template('user.html',uname=request.user.uname,files = {file.fileid:file.filename for file in db_session.query(Metadata).filter_by(userid=request.user.userid).all()})

@app.route('/upload', methods = ['POST'])
@requires_auth
def upload():
    file=request.files['form_file']
    if file.filename!="":
        if not file.filename.split(".")[-1].lower().endswith(("png","jpg","jpeg")):
            return redirect("/user?error=File not supported")
    else:
        return redirect("/user?error=No file provided")
    fileid = str(secrets.token_hex(16))
    file.save(os.path.join("./files", os.path.basename(file.filename)))
    file = request.files['form_file']
    blob = bucket.blob(f'uploads/{fileid}')
    file.seek(0)
    blob.upload_from_file(file, content_type=file.content_type)
    image = Image.open(os.path.join("./files", file.filename))
    exif_dict = {}
    exifdata = image._getexif()
    exifavailable = False
    if exifdata is not None:
        exifavailable = True
        for tagid, value in exifdata.items():
            tagname = ExifTags.TAGS.get(tagid, tagid)
            exif_dict[tagname] = str(value)
    
    os.remove(image.filename)
    file = Metadata(
        fileid=fileid,
        filename=image.filename.split("/")[-1],
        bucket=bucket_name,
        loc_in_bucket=f'uploads/{fileid}',
        image_size=str(image.size),
        image_height=image.height,
        image_width=image.width,
        image_format=image.format,
        image_mode=image.mode,
        image_is_animated=getattr(image, "is_animated", False),
        frames_in_image=getattr(image, "n_frames", 1),
        exif_data_available=exifavailable,
        exif_data=json.dumps(exif_dict),
        userid=request.user.userid
    )
    db_session.add(file)
    db_session.commit()
    return redirect(f"/user?success=Successfully upload file {file.filename}") 

def object_as_dict(obj):
    return {col.name: (getattr(obj, col.name) if col.name != "exif_data" else json.loads(getattr(obj, col.name))) for col in obj.__table__.columns}

@app.route('/files/<fileid>')
@requires_auth
def get_file(fileid):
    file = db_session.query(Metadata).filter_by(userid=request.user.userid,fileid=fileid).first()
    if file:
        return render_template("image.html", uname=request.user.uname, fileid=file.fileid, filename = file.filename, filedata=object_as_dict(file))
    else:
        return redirect("/user?error=No file at the url")

@app.route('/image/<fileid>')
@requires_auth
def get_image(fileid):
    file = db_session.query(Metadata).filter_by(fileid=fileid,userid=request.user.userid).first()
    return send_file(bucket.blob(file.loc_in_bucket).open('rb'),download_name=file.filename)

@app.route('/update/<fileid>', methods=['GET', 'POST'])
@requires_auth
def update_file(fileid):
    file = db_session.query(Metadata).filter_by(fileid=fileid,userid=request.user.userid).first()
    if file == None:
        return redirect(f"/user?error=No file at the url")
    if request.method == 'POST':
        new_file = request.files['form_file']
        if new_file.filename:
            if not new_file.filename.split(".")[-1].lower().endswith(("png","jpg","jpeg")):
                return redirect(f"/update/{fileid}?error=File not supported")
            new_file.save(os.path.join("./files", new_file.filename))
            image = Image.open(os.path.join("./files", new_file.filename))
            exif_dict = {}
            exifdata = image._getexif()
            exifavailable = False
            if exifdata is not None:
                exifavailable = True
                for tagid, value in exifdata.items():
                    tagname = ExifTags.TAGS.get(tagid, tagid)
                    exif_dict[tagname] = str(value)
            file.filename=image.filename.split("/")[-1]
            file.bucket=bucket_name
            file.image_size=str(image.size)
            file.image_height=image.height
            file.image_width=image.width
            file.image_format=image.format
            file.image_mode=image.mode
            file.image_is_animated=getattr(image, "is_animated", False)
            file.frames_in_image=getattr(image, "n_frames", 1)
            file.exif_data_available=exifavailable
            file.exif_data=json.dumps(exif_dict)
            db_session.commit()
            bucket.delete_blob(f"{file.loc_in_bucket}")
            new_file.seek(0)
            blob = bucket.blob(f"{file.loc_in_bucket}")
            blob.upload_from_string(new_file.read(), content_type=new_file.content_type)
            os.remove(f"./files/{new_file.filename}")
            return redirect(f'/files/{fileid}?success=Successfully update this file')
        else:
            return redirect(f'/update/{fileid}?error=No file provided')
    return render_template('update.html', uname=request.user.uname, fileid=file.fileid, filename = file.filename, filedata=object_as_dict(file))

@app.route('/delete/<fileid>')
@requires_auth
def delete_file(fileid):
    file = db_session.query(Metadata).filter_by(fileid=fileid,userid=request.user.userid).first()
    if file:
        db_session.delete(file)
        db_session.commit()
        bucket.delete_blob(file.loc_in_bucket)
        return redirect(f'/user?success=Successfully Deleted {file.filename}')
    else:
        return redirect(f"/user?error=No file at the url")

@app.route("/signout")
@requires_auth
def logout():
    if session.get("uname") != None and session.get("userid")!=None:
        session.clear()
        return redirect(f"/?success=Successfully signed out")

@app.route("/listfiles/<num>")
@requires_auth
def list_files(num):
    files = []
    for file in db_session.query(Metadata).filter_by(userid=request.user.userid).limit(int(num)).all():
        files.append(file.filename)
    return files

@app.route("/chpasswd",methods=["GET","POST"])
def chpasswd():
    if request.method == "GET":
        if session.get('uname') != None and session.get('userid') != None:
            return render_template("chpasswd.html", uname=session.get('uname'))
        else:
            return render_template("chpasswd.html")
    elif request.method == "POST":
        uname = request.form["uname"]
        opasswd = request.form["opasswd"]
        npasswd = request.form["npasswd"]
        cpasswd = request.form["cpasswd"]
        user = db_session.query(User).filter_by(uname=uname).first()
        err = {}
        val = validatePassword(npasswd)
        if not val[0]:
            err["npasswd"] = val[1]
        if npasswd != cpasswd:
            err["cpasswd"] = "Passwords do not match"
        if opasswd == npasswd:
            err["npasswd"] = "New password cannot be same as old password"
        if str(hashlib.sha256((opasswd+user.salt).encode()).hexdigest()) != user.passwd:
            err["opasswd"] = "Present password is Incorrect"
        if err:
            return jsonify(err)
        else:
            user.passwd = str(hashlib.sha256((npasswd+user.salt).encode()).hexdigest())
            db_session.commit()
            return jsonify({"message": "Successfully updated the password you can use the new password from next login"})

if __name__ == '__main__':
    app.run('0.0.0.0', port=os.environ["PORT"])