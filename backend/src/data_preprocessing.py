import pandas as pd

def load_data(path):
    df = pd.read_csv(path)
    return df

def preprocess_data(df):

    df = df.drop_duplicates()
    df = df.dropna()

    # Convert status to label (if not already)
    if "status" in df.columns:
        df["label"] = df["status"].apply(lambda x: 1 if x == "legitimate" else 0)
        df = df.drop(columns=["status"])

    return df