import json
import urllib.request

URL = "https://hugovk.github.io/top-pypi-packages/top-pypi-packages-30-days.min.json"
TOP_N = 1000


def fetch_top_packages(url: str = URL, top_n: int = TOP_N) -> list[dict]:
    with urllib.request.urlopen(url) as resp:
        data = json.loads(resp.read())

    print(f"Last updated: {data['last_update']}")
    print(f"Total packages in dataset: {len(data['rows']):,}")

    rows = data["rows"][:top_n]
    print(f"\nTop {top_n} packages by 30-day downloads:\n")
    print(f"{'Rank':<6} {'Package':<40} {'Downloads':>15}")
    print("-" * 63)
    for i, row in enumerate(rows, 1):
        print(f"{i:<6} {row['project']:<40} {row['download_count']:>15,}")

    return rows


if __name__ == "__main__":
    fetch_top_packages()
