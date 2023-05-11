import time
import random

from flask import Flask
from flask import request
from flask_cors import CORS
from flask_cors import cross_origin


application = Flask(__name__)
cors = CORS(application)
application.config["CORS_HEADERS"] = "Content-Type"


@application.route("/")
@cross_origin()
def index():
    return "Hello World"


@application.route("/detect", methods=["POST"])
@cross_origin()
def detect():
    data = request.get_json()
    if "url" in data:
        url = data["url"]
        print(url)
        time.sleep(1)
        response = {
            "code": random.randint(-1, 1),
            "message": "success"
        }
    else:
        response = {
            "code": -1,
            "message": "url not found"
        }
    return response


if __name__ == "__main__":
    # application.debug = True
    application.run(host="0.0.0.0", port=5000)
    application.run()
