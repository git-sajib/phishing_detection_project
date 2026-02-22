import csv

def generate_legitimate():
    urls = [
        ["https://google.com", 1],
        ["https://facebook.com", 1],
        ["https://github.com", 1],
        ["https://openai.com", 1],
        ["https://wikipedia.org", 1],
        ["https://amazon.com", 1],
        ["https://microsoft.com", 1],
        ["https://apple.com", 1],
        ["https://stackoverflow.com", 1],
        ["https://youtube.com", 1],
        ["https://linkedin.com", 1],
        ["https://twitter.com", 1],
        ["https://instagram.com", 1],
        ["https://reddit.com", 1],
        ["https://cloud.google.com", 1],
        ["https://aws.amazon.com", 1],
        ["https://azure.microsoft.com", 1],
        ["https://paypal.com", 1],
        ["https://stripe.com", 1],
    ]

    with open("data/raw/legitimate.csv", "w", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["url", "label"])
        writer.writerows(urls)

    print("Legitimate dataset generated")

if __name__ == "__main__":
    generate_legitimate()