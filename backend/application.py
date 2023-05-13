import os
import pickle
import pandas as pd

from flask import Flask
from flask import request
from flask_cors import CORS
from flask_cors import cross_origin
from urllib.parse import urlparse
from ssl_checker import export
from features import PhishFeatures


MODEL_PATHS = {
    "random-forest": "classifiers/random-forest.pkl",
    "scaler": "classifiers/scaler.pkl",
    "pca": "classifiers/pca.pkl",
}

scaler = pickle.load(open(MODEL_PATHS["scaler"], "rb"))
pca = pickle.load(open(MODEL_PATHS["pca"], "rb"))
classifier = pickle.load(open(MODEL_PATHS["random-forest"], "rb"))

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
    host = "https://" + urlparse(url).netloc
    cert_info_path = export(host)
    if cert_info_path:
        cert_info = PhishFeatures().compute_samples(cert_info_path)
        os.remove(cert_info_path)
        features = PhishFeatures().compute_features(cert_info)
        print(features)
        scaled_features = scaler.transform(features)
        pca_features = pd.DataFrame(data=pca.transform(scaled_features),
                                    columns=["PC" + str(i + 1) for i in range(150)])
        print(pca_features)
        score = classifier.predict_proba(pca_features)[:, 1]
        print(score)
    return {
        "code": 1,
        "message": "success"
    }


if __name__ == "__main__":
    # application.debug = True
    application.run(host="0.0.0.0", port=5000)
    application.run()
