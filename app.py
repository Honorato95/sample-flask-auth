from flask import Flask, jsonify, request
from models.user import User
from database import db
import bcrypt
from flask_login import LoginManager, login_user, current_user, logout_user, login_required

app = Flask(__name__)
app.config["SECRET_KEY"] = "password"
app.config["SQLALCHEMY_DATABASE_URI"] = "mysql+pymysql://root:administrator@127.0.0.1:3306/flask-crud"

login_manager = LoginManager()
db.init_app(app)
login_manager.init_app(app)

login_manager.login_view = "login"

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)

@app.route("/login", methods=["POST"])
def login():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    if username and password:
        user = User.query.filter_by(username=username).first()
        if user and bcrypt.checkpw(str.encode(password), str.encode(user.password)):
            login_user(user)
            return jsonify({"message": "Autenticação realizada."}), 200
        
    return jsonify({"message": "Credenciais inválidas."}), 404

@app.route("/logout", methods=["GET"])
@login_required
def logout():
    logout_user()
    return jsonify({"message": "Logout realizado."})

@app.route("/user", methods=["POST"])
def create_user():
    data = request.json
    username = data.get("username")
    password = data.get("password")
    role = data.get("role", "user")

    if username and password:
        hashed_password = bcrypt.hashpw(str.encode(password), bcrypt.gensalt())
        user = User(username=username, password=hashed_password, role=role)
        db.session.add(user)
        db.session.commit()
        return jsonify({"message": "Usuário cadastrado."}), 201

    return jsonify({"message": "Informações inválidas"}), 400 

@app.route("/user", methods=["GET"])
@login_required
def read_users():
    users = User.query.all()
    if users:
        return jsonify({"users": [{"username": user.username, "role": user.role} for user in users]}), 200
        
    return jsonify({"message":"Nenhum usuário cadastrado"}), 404

@app.route("/user/<int:id_user>", methods=["GET"])
@login_required
def read_user(id_user):
    user = User.query.get(id_user)
    if user:
        return {"username": user.username, "role": user.role}
        
    return jsonify({"message":"Usuário não encotrado"}), 404

@app.route("/user/<int:id_user>", methods=["PUT"])
@login_required
def update_user(id_user):
    data = request.json
    user = User.query.get(id_user)
    if id_user != current_user.id and current_user.role == "user":
        return jsonify({"message": "Operação não permitida"}), 403

    if user and data.get("password"):
        user.password = data.get("password")
        db.session.commit()
        return jsonify({"message": f"Senha alterada para usuário id {id_user}"})
    

    return jsonify({"message":"Usuário não encontrado"}), 404

@app.route("/user/<int:id_user>", methods=["DELETE"])
@login_required
def delete_user(id_user):
    user = User.query.get(id_user)

    if current_user.role != "admin":
        return jsonify({"message": "Operação não permitida"}), 403
    
    if id_user == current_user.id:
        return jsonify({"message":"Não permitido excluir este usuário"}), 403
    
    if user:
        db.session.delete(user)
        db.session.commit()
        return jsonify({"message":f"Usuário {user.username} excluído."})
    
    return jsonify({"message":"Usuário não encontrado"}), 404

if __name__ == "__main__":
    app.run(debug=True)