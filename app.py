from flask import *
import pymongo #載入 pymongo
#連線到 MongoDB雲端資料庫
from pymongo.mongo_client import MongoClient
from pymongo.server_api import ServerApi
import secrets
from datetime import datetime, timedelta, timezone
from flask_mail import Mail, Message
from dotenv import load_dotenv
import os


#伺服器基本設置
app = Flask(
    __name__
    , static_folder="static" #靜態資料夾名稱
    , static_url_path= "/" #靜態檔案對應的網址路徑
) 
load_dotenv()
app.secret_key = os.getenv('SECRET_KEY') #Session的密鑰設定

user = os.getenv("MONGO_USER")
password = os.getenv("MONGO_PASS")
cluster = os.getenv("MONGO_CLUSTER")
uri = f"mongodb+srv://{user}:{password}@{cluster}/?retryWrites=true&w=majority&appName=Cluster0&authSource=admin"

# Create a new client and connect to the server
client = MongoClient(uri, server_api=ServerApi('1'))
db = client.web2 # 選擇要操作資料庫

#首頁
@app.route("/")
def idex():
    return render_template("login.html")

#使用POST方始建立路由
@app.route("/signup", methods=["GET", "POST"])
def signup():
    if request.method == "POST":
        collection = db.users # 選擇要操作集合
        user_name = request.form["user_name"]
        user_email = request.form["signup_email"]
        user_password = request.form["signup_password"]
        confirm_password = request.form["confirm_password"]
        #檢查密碼與確認密碼是否一致
        if user_password != confirm_password:
            return redirect("/message?msg=密碼與確認密碼不一致")
        #檢查信箱是否已被註冊
        result = collection.find_one({"email": user_email})
        result2 = collection.find_one({"name": user_name})
        if result != None:
            return redirect("/message?msg=信箱已被註冊")
        if result2 != None:
            return redirect("/message?msg=暱稱已被使用")
        collection.insert_many([{
            "name": user_name,
            "email": user_email,
            "password": user_password
            }])
        session["nickname"] = user_name
        return redirect("/member")
    return render_template("signup.html")

@app.route("/member")
def member():
    if "nickname" in session:
        return render_template("member.html")
    else:
        return redirect("/")
        
@app.route("/login", methods=["GET", "POST"])
def login():
    if request.method == "POST":
        collection = db.users # 選擇要操作集合
        #取form表單輸入帳密
        type_email = request.form["login_email"]
        type_password = request.form["login_password"]
        #從資料庫取出帳密
        user = collection.find_one({
            "$and": [
            {"email": type_email},
            {"password": type_password}]})
        if user == None:
            return redirect("/message?msg=密碼錯誤或帳號不存在")
        session["nickname"] = user["name"]
        return redirect("/member")
    return render_template("login.html")

#SMTP服務,驗證信件初始設定
load_dotenv()

app.config.update({
    'MAIL_SERVER': os.getenv('MAIL_SERVER'),
    'MAIL_PORT': int(os.getenv('MAIL_PORT')),
    'MAIL_USE_TLS': os.getenv('MAIL_USE_TLS') == 'True',
    'MAIL_USERNAME': os.getenv('MAIL_USERNAME'),
    'MAIL_PASSWORD': os.getenv('MAIL_PASSWORD'),
    'MAIL_DEFAULT_SENDER': os.getenv('MAIL_DEFAULT_SENDER')
})

mail = Mail(app)

#發送忘記密碼驗證信
@app.route("/sendEmail", methods=["GET", "POST"])
def sendEmail():
    if request.method == "POST":
        collection = db.users # 選擇要操作集合
        type_email = request.form["forgot_password"]
        user = collection.find_one({"email": type_email})
        if user == None:
            return redirect("/message?msg=查無此信箱")
        token = secrets.token_urlsafe(nbytes=32)  # 可選參數 nbytes，預設為 32
        timeSet = datetime.now() + timedelta(minutes=15) #設定時間
        #將token存入資料庫
        collection2 = db.tokens # 選擇要操作集合
        collection2.insert_many([{
            "email": type_email,
            "token": token,
            "time_limit": timeSet
            }])
        #建立信件內容
        base_url = os.getenv("BASE_URL")
        verify_url = f"{base_url}/passwordForgot?token={token}"
        msg = Message(
        subject="請驗證您的帳號",
        recipients=[type_email],
        body = "請點擊以下連結完成驗證：\n" + verify_url)
    #發送信件
    mail.send(msg)
    return render_template("sendEmail.html")   
    
@app.route("/message")
def message():
    message = request.args.get("msg")
    return render_template("message.html", message = message)

@app.route("/logout")
def logout():
    del session["nickname"]
    return redirect("/")

@app.route("/emailForgot")
def emailForgot():
    return render_template("email-forgot.html")

@app.route("/passwordForgot", methods=["GET", "POST"])
def passwordForgot():
    if request.method == "POST":
        user_email = request.form["email"]
        new_password = request.form["new_password"]
        confirm_password = request.form["confirm_password"]
        if new_password != confirm_password:
            return redirect("/message?msg=密碼與確認密碼不一致")
        collection = db.users
        collection.update_one(
            {"email": user_email}, # 篩選條件
            {"$set": {"password": new_password}} # 更新操作
        )
        return redirect("/message?msg=密碼已更新，請重新登入")
    token = request.args.get("token")
    collection = db.tokens
    result = collection.find_one({"token": token})
    current_time = datetime.now()
    user_email = result["email"]
    if result == None or current_time > result["time_limit"]:
        return redirect("/message?msg=驗證信件已失效或錯誤")
    return render_template("password-forgot.html", token=token, user_email=user_email)

app.run(host="0.0.0.0", port = 3000)


