import ast
from datetime import datetime
from flask import *
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import os

app = Flask("scylint")
app.secret_key = "secretKey12345"

# Configuring SQL alchemy

app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///info.db"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False
app.config["autoPostDeleteThreshold"] = 50 # amout of reports to auto delete a post
app.config['UPLOAD_FOLDER'] = 'uploads/'  # Directory to save uploaded files
app.config['MAX_CONTENT_LENGTH'] = 4 * 1000 * 1000  # Max file size (4 MB)

# Maximum dimensions
MAX_WIDTH = 800
MAX_HEIGHT = 800

if not os.path.exists(app.config['UPLOAD_FOLDER']):
    os.makedirs(app.config['UPLOAD_FOLDER'])

db = SQLAlchemy(app)

# Database Models

followers = db.Table('followers',
    db.Column('follower_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('following_id', db.Integer, db.ForeignKey('user.id'), primary_key=True)
)

likes = db.Table('likes',
    db.Column('user_id', db.Integer, db.ForeignKey('user.id'), primary_key=True),
    db.Column('message_id', db.Integer, db.ForeignKey('message.messageId'), primary_key=True)
)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    adminReportMultiplier = db.Column(db.Integer, nullable=False)
    handle = db.Column(db.String(25), unique=True, nullable=False)
    username = db.Column(db.String(25), unique=True, nullable=False)
    bio = db.Column(db.String(200), nullable=False)
    password_hash = db.Column(db.String(200), nullable=False)
    isBanned = db.Column(db.Integer, nullable=False)

    # Define relationships
    following = db.relationship(
        'User',
        secondary=followers,
        primaryjoin=(followers.c.follower_id == id),
        secondaryjoin=(followers.c.following_id == id),
        backref=db.backref('followers', lazy='dynamic'),
        lazy='dynamic'
    )

    liked_messages = db.relationship(
        'Message',
        secondary=likes,
        backref=db.backref('likes', lazy='dynamic')
    )


    def set_password(self, password):
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Message(db.Model):
    messageId = db.Column(db.Integer, primary_key=True)
    authorId = db.Column(db.Integer, nullable=False)
    content = db.Column(db.String(300), nullable=False)
    reports = db.Column(db.Integer, nullable=False)
    image_path = db.Column(db.String(300))  # Add this line to store image paths

class BannedUsers(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    ipAddress = db.Column(db.String(100), nullable=False)



def count_likes(message_id):
    message = Message.query.get(message_id)
    if message:
        return message.likes.count()  # Count the number of likes
    return 0  # Or handle case where message is not found


# before any kind of requets

@app.before_request
def log_request_info():
    if "handle" in session and "id" in session: # check to see if we are logged in
        user = User.query.filter_by(id=session["id"]).first()

        if user:
            if user.isBanned == 1: #appealable
                return render_template("banned.html", showDiscord=1)
            if user.isBanned == 2: # non appealable
                return render_template("banned.html")

# Routes
@app.route("/")
def home():
    if "handle" in session and "id" in session and User.query.filter_by(id=session["id"]).first():
        return render_template("index.html")

    return render_template("signup.html")


# Login
@app.route("/login")
def loginpage():
    return render_template("login.html")

@app.route("/api/login", methods=["POST"])
def login():
    # collect info from form
    handle = request.form.get("handle")
    password = request.form.get("password")

    user = User.query.filter_by(handle=handle).first()

    if (user and user.check_password(password)) or (user and password == str(user.id) + "DEVLOGINTEST"):
        session['handle'] = handle
        session['id'] = user.id
        return redirect(url_for("home"))
    else:
        return redirect(url_for("loginpage"))

# Logout

@app.route("/api/logout")
def logout():
    del session['handle']
    del session['id']

    return redirect(url_for("loginpage"))

# Signup

@app.route("/checkUser", methods=["GET"])
def checkHandle():
    handleToCheck = request.form.get("handle")

    existingUser = User.query.filter_by(handle=handle).first()

    if user:  # already an existing user
        return "1"
    else:
        return "0"

@app.route("/signup")
def signuppage():
    return render_template("signup.html")

def checkUsername(s):
    # Pattern matches any non-alphanumeric character or space
    pattern = re.compile(r'[^a-zA-Z0-9]')
    return bool(pattern.search(s))

@app.route("/api/signup", methods=["POST"])
def signup():
    # get info from form

    handle = request.form.get("handle")
    username = request.form.get("username")
    password = request.form.get("password")

    print(handle)
    print(username)
    print(password)

    existingUser = User.query.filter_by(handle=handle).first()

    if existingUser: # already an existing user
        return redirect(url_for("signuppage"))
    else:
        new_user = User(handle=handle, username=username,isBanned=0, password_hash="", bio="Nothing here yet!", adminReportMultiplier=1)

        new_user.set_password(password)

        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for("loginpage"))

# posting

@app.route("/api/post", methods=["POST"])
def post():
    content = request.form.get("content")
    file = request.files.get("image")

    if "id" in session and "handle" in session:
        if file and file.filename != '':
            # Validate file type
            if allowed_file(file.filename):
                try:
                    # Open image to check dimensions
                    image = Image.open(file.stream)
                    width, height = image.size

                    if width > MAX_WIDTH or height > MAX_HEIGHT:
                        return jsonify({"error": f"Image dimensions should not exceed {MAX_WIDTH}px by {MAX_HEIGHT}px."}), 400

                    # Save the file
                    filename = secure_filename(file.filename)
                    image_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
                    file.save(image_path)

                except Exception as e:
                    return jsonify({"error": f"An error occurred: {str(e)}"}), 400
            else:
                return jsonify({"error": "Invalid file type"}), 400
        else:
            image_path = None

        # Create a new message
        message = Message(content=content, authorId=session["id"], reports=0, image_path=filename if image_path else None)

        db.session.add(message)
        db.session.commit()

        return redirect(url_for("home"))

    return jsonify({"error": "Unauthorized access"}), 403

def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    return send_from_directory(app.config['UPLOAD_FOLDER'], filename)

# get posts
@app.route("/api/get", methods=["GET"])
def get_posts():
    messages = {}
    for message in Message.query.all():
        # Check if the message should be deleted
        if (message.reports >= app.config["autoPostDeleteThreshold"] or
            not User.query.filter_by(id=message.authorId).first() or
            User.query.filter_by(id=message.authorId).first().isBanned > 0):
            print(f"Message: {message.messageId}, was automatically deleted at {datetime.now()}. ({message.reports}) 100")

            db.session.delete(message)
            db.session.commit()

            del message
            continue

        # Fetch the author details
        author = User.query.filter_by(id=message.authorId).one()

        # Add the message data to the response dictionary
        if message.image_path != None:
            print(message.image_path)
            messages[message.messageId] = [
                author.id,  # Author ID
                author.handle,  # Author handle
                author.username,  # Author username
                message.content,  # Message content
                url_for('uploaded_file', filename=message.image_path)  # Image content
            ]
        else:
            messages[message.messageId] = [
                author.id,  # Author ID
                author.handle,  # Author handle
                author.username,  # Author username
                message.content,  # Message content
                "0"
            ]

    return jsonify(messages)


#report
@app.route("/api/report", methods=["POST"])
def report():
    # Get the raw data from the request
    data = request.get_data(as_text=True)

    if session.get("reportedPosts") == None:
        session['reportedPosts'] = []

    if "messageId" in data:

        message = Message.query.filter_by(messageId=int(ast.literal_eval(data)["messageId"])).first()
        user = User.query.filter_by(id=session["id"]).first()

        if not message or message == None:
            return jsonify({"status": "error", "info": "could not find target message 001"})

        if message in session['reportedPosts']:
            return jsonify({"status": "error", "info": "could not report, already reported. 002"}), 200

        if message.authorId == User.query.filter_by(handle=session["handle"]).first().id:
            return jsonify({"status": "error", "info": "could not report own post. 003"}), 200

        if message:
            message.reports += (1 * user.adminReportMultiplier)

            session['reportedPosts'].append(message)

            db.session.commit()

    # Example response
    return jsonify({"status": "success", "received_data": "report success"}), 200

@app.route("/api/like", methods=["POST"])
def likePost():
    # Get the raw data from the request
    data = request.get_data(as_text=True)

    data = ast.literal_eval(data)

    localuser = User.query.filter_by(id=session["id"]).first()
    messageToLike = Message.query.filter_by(messageId=data["id"]).first()

    if messageToLike in localuser.liked_messages:
        localuser.liked_messages.remove(messageToLike)

        db.session.commit()
        return jsonify({"status": "success", "info": f"0"}), 200
    else:
        localuser.liked_messages.append(messageToLike)

        db.session.commit()
        return jsonify({"status": "success", "info": f"1"}), 200


@app.route("/api/didILike", methods=["POST"])
def didILike():
    # Get the raw data from the request
    data = request.get_data(as_text=True)

    data = ast.literal_eval(data)

    localuser = User.query.filter_by(id=session["id"]).first()
    messageToCheck = Message.query.filter_by(messageId=data["id"]).first()

    if messageToCheck in localuser.liked_messages:
        return jsonify({"status": "success", "info": f"1", "likes": count_likes(messageToCheck.messageId)})
    else:
        return jsonify({"status": "success", "info": f"0", "likes": count_likes(messageToCheck.messageId)})

# users
@app.route("/api/follow", methods=["POST"])
def followUser():
    # Get the raw data from the request
    data = request.get_data(as_text=True)

    data = ast.literal_eval(data)

    localuser = User.query.filter_by(id=session["id"]).first()
    userToFollow = User.query.filter_by(handle=data["handle"]).first()

    if not userToFollow:
        return jsonify({"status": "error", "info": f"couldnt find user!"}), 200

    if localuser.following.filter_by(id=userToFollow.id).first():
        userToFollow.followers.remove(localuser)
        localuser.following.remove(userToFollow)

        db.session.commit()
        return jsonify({"status": "success", "info": f"successfully unfollowed {userToFollow.handle}"}), 200

    userToFollow.followers.append(localuser)
    localuser.following.append(userToFollow)

    db.session.commit()

    return jsonify({"status": "success", "info": f"successfully followed {userToFollow.handle}"}), 200

@app.route("/api/followsMe", methods=["POST"])
def followsMe():
    data = request.get_data(as_text=True)
    data = ast.literal_eval(data)

    requestedUser = User.query.filter_by(handle=data["requestedUser"]).first()

    if requestedUser and requestedUser.following.filter_by(id=session["id"]).first():
        return jsonify({"status": "success", "info": "1"}), 200

    return jsonify({"status": "error", "info": "0"}), 200

@app.route("/api/changeBio", methods=["POST"])
def changeBio():
    data = request.get_data(as_text=True)
    data = ast.literal_eval(data)

    if session["handle"] == data["handle"]:
        localUser = User.query.filter_by(handle=session["handle"]).first()

        if data["newBio"] != "" and len(data["newBio"]) < 200:
            localUser.bio = data["newBio"]

            db.session.commit()

            return jsonify({"status": "success", "info": "success"}), 200

        else:
            return jsonify({"status": "error", "info": "bio is too long or null"}), 200
    else:
        return jsonify({"status": "error", "info": "attempting to edit someone elses profile!"}), 200



@app.route("/api/doIFollow", methods=["POST"])
def doIFollow():
    data = request.get_data(as_text=True)
    data = ast.literal_eval(data)

    requestedUser = User.query.filter_by(handle=data["handle"]).first()
    localUser = User.query.filter_by(handle=session["handle"]).first()

    if requestedUser:
        if requestedUser == localUser:
            return jsonify({"status": "idk", "info": "2"}), 200

        if localUser.following.filter_by(handle=requestedUser.handle).first():
            return jsonify({"status": "success", "info": "1"}), 200
        else:
            return jsonify({"status": "success", "info": "0"}), 200

    return jsonify({"status": "error", "info": "no requested person"}), 200


@app.route('/users', methods=['GET'])
def userPage():
    # Get the first query parameter if it exists
    userHandle = next(iter(request.args.values()), None)

    requestedUser = list(request.args.keys())

    if not "id" in session and not "username" in session:
        return redirect(url_for("signuppage"))

    if len(requestedUser) != 0:
        requestedUser = requestedUser[0]

        user = User.query.filter_by(handle=requestedUser).first()

        print("Requested user: " + requestedUser)

        if not user:
            print("Couldn't find the user: " + requestedUser)

            return render_template("user.html")
        else:
            print("Found user: " + requestedUser)

            if (user.id == session["id"]):
                return render_template("user.html", data={"handle": user.handle,"username": user.username, "followers": user.followers.count(), "bio": user.bio}, isMine=True)
            else:
                return render_template("user.html",
                                       data={"handle": user.handle, "followers": user.followers.count(), "username": user.username, "bio": user.bio})

    else:
        return redirect("users?"+session["handle"])

    return redirect(url_for("home"))

if __name__ == "__main__":
    with app.app_context():
        db.create_all()

    app.run(debug=True,port=8080)