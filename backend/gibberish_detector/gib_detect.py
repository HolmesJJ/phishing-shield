import pickle
import gib_detect_train

model_data = pickle.load(open("gib_model.pki", "rb"))

if __name__ == "__main__":
    words = ["baidu", "google", "microsoft", "fajvfav", "www"]
    model_mat = model_data['mat']
    for word in words:
        print(gib_detect_train.avg_transition_prob(word, model_mat))
