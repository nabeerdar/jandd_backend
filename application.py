# from flask import Flask, request, jsonify
# from flask_cors import CORS

# app = Flask(__name__)

# CORS(app)

# @app.route("/staff", methods=['POST'])
# def home():
#     data = request.get_json()
#     print("Received data:", data)
#     return jsonify({"message": "Data received successfull, mehmat!"}), 200

# if __name__ == "__main__":
#     app.run()

from app import create_app


app = create_app()

if __name__ == "__main__":
    app.run()
