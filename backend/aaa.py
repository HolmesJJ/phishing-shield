import pickle
import pandas as pd

if __name__ == "__main__":
    # a = pickle.load(open("feature_columns.pkl", "rb"))
    b = pd.read_csv("feature_columns.csv")[0].values
    print(b)
