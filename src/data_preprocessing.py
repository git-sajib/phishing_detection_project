import pandas as pd

def load_data(path):
    df = pd.read_csv(path)
    return df

def preprocess_data(df):
    df = df.drop_duplicates()
    df = df.dropna()
    return df