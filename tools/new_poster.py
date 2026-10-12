#!/usr/bin/env python3
import argparse
import csv
import secrets
from pathlib import Path

BASE_URL = "https://kuski.qd.je/"
CSV_PATH = Path(__file__).resolve().parent.parent / "posters.csv"


def main():
    parser = argparse.ArgumentParser(description="Create a short random poster id.")
    parser.add_argument("label", nargs="?", default="", help="Where this poster will be placed")
    args = parser.parse_args()

    poster_id = secrets.token_hex(3)  # 6 random hex chars
    url = f"{BASE_URL}?p={poster_id}"

    exists = CSV_PATH.exists()
    with CSV_PATH.open("a", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        if not exists:
            writer.writerow(["poster_id", "label", "url"])
        writer.writerow([poster_id, args.label, url])

    print(f"ID:  {poster_id}")
    print(f"URL: {url}")
    if args.label:
        print(f"Lokacija: {args.label}")
    print(f"Shranjeno: {CSV_PATH}")


if __name__ == "__main__":
    main()
