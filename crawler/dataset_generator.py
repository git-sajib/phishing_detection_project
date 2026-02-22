import pandas as pd

def generate_dataset():
    phishing = pd.read_csv("data/raw/phishtank.csv")
    legit = pd.read_csv("data/raw/legitimate.csv")

    df = pd.concat([phishing, legit])
    df = df.sample(frac=1).reset_index(drop=True)

    df.to_csv("data/phishing_large.csv", index=False)

    print("Dataset created:", len(df))

if __name__ == "__main__":
    generate_dataset()