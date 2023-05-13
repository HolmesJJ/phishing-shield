from flask import Flask
from flask import request
from flask_cors import CORS
from flask_cors import cross_origin
from urllib.parse import urlparse
from ssl_checker import CertInfo


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
    if "url" not in data:
        return {
            "code": -1,
            "message": "url not found"
        }
    url = data["url"]
    if not url.startswith("http://") and not url.startswith("https://"):
        return {
            "code": -1,
            "message": "success"
        }
    host = "https://" + urlparse(url).netloc + "/"
    cert_info = CertInfo(host, keep_cert=False).get_info(convert_to_df=True)
    print(cert_info)
    return {
        "code": 1,
        "message": "success"
    }


if __name__ == "__main__":
    # application.debug = True
    application.run(host="0.0.0.0", port=5000)
    application.run()
