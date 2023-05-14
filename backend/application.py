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
    "pca1": "classifiers/pca1.pkl",
    "scaler1": "classifiers/scaler1.pkl",
    "random-forest1": "classifiers/random-forest1.pkl",
    "random-forest2": "classifiers/random-forest2.pkl",
}

scaler1 = pickle.load(open(MODEL_PATHS["scaler1"], "rb"))
pca1 = pickle.load(open(MODEL_PATHS["pca1"], "rb"))
classifier1 = pickle.load(open(MODEL_PATHS["random-forest1"], "rb"))
classifier2 = pickle.load(open(MODEL_PATHS["random-forest2"], "rb"))

CLASSIFIER = 1

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
    if cert_info_path is None:
        return {
            "code": -1,
            "message": "success"
        }
    cert_info = PhishFeatures().compute_samples(cert_info_path)
    os.remove(cert_info_path)
    if CLASSIFIER == 1:
        features = PhishFeatures().compute_features(cert_info, classifier=1)
        scaled_features = scaler1.transform(features)
        pca_features = pd.DataFrame(data=pca1.transform(scaled_features),
                                    columns=["PC" + str(i + 1) for i in range(150)])
        score = classifier1.predict_proba(pca_features)[:, 1]
    else:
        features = PhishFeatures().compute_features(cert_info, classifier=2)
        score = classifier2.predict_proba(features)[:, 1]
    print(score)
    return {
        "code": 1 if score > 0.5 else 0,
        "message": "success"
    }


if __name__ == "__main__":
    # application.debug = True
    application.run(host="0.0.0.0", port=5000)
    application.run()
