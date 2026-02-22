import requests
import csv

API_URL = "http://data.phishtank.com/data/online-valid.json"

def fetch_phishtank_data():
    response = requests.get(API_URL)

    if response.status_code != 200:
        print("Failed to fetch data")
        return []

    data = response.json()
    urls = []

    for entry in data:
        url = entry.get("url")
        if url:
            urls.append([url, 0])  # 0 = phishing

    return urls

def save_to_csv(urls, path="data/raw/phishtank.csv"):
    with open(path, "w", newline="", encoding="utf-8") as file:
        writer = csv.writer(file)
        writer.writerow(["url", "label"])
        writer.writerows(urls)

    print(f"Saved {len(urls)} records")

if __name__ == "__main__":
    urls = fetch_phishtank_data()
    save_to_csv(urls)