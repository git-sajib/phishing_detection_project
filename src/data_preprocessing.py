import pandas as pd

def load_data(path):
    return pd.read_csv(path)

def preprocess_data(df):
    df = df.drop_duplicates()
    df = df.dropna()
    df['label'] = df['label'].astype(int)
    return df