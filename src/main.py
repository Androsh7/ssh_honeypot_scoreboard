"""Main logic"""

# Standard libraries
import argparse
import re
import json
from collections import Counter
from datetime import datetime
from pathlib import Path

LOG_REGEX = r"\[([a-zA-Z]{1,3} [a-zA-Z]{1,3} \d{2} \d{2}\:\d{2}\:\d{2} \d{4})\] ((\d{1,3}\.)+\d{1,3}) (\w+) (.+)"
LOG_STRFTIME_FORMAT = r"%a %b %d %H:%M:%S %Y"


def parse_honeypot_log(
    file_path: Path,
    date_list: list[datetime],
    ip_list: list[str],
    username_list: list[str],
    password_list: list[str],
):
    """Parses an ssh honeypot file and updates the provided lists

    Args:
        file_path: The file to parse
        date_list: The output list for all dates found
        ip_list: The output list for all IP addresses
        username_list: The output list for all usernames
        password_list: The output list for all passwords
    """
    # Read the honeypot file
    with open(file=file_path, mode="r", encoding="utf-8") as honeypot_file:
        honeypot_log = honeypot_file.readlines()

    # Break the logs into the date, ip, username, and password lists
    for line in honeypot_log:
        if (result := re.search(LOG_REGEX, string=line)) is not None:
            date_list.append(datetime.strptime(result.group(1), LOG_STRFTIME_FORMAT))
            ip_list.append(result.group(2))
            username_list.append(result.group(4))
            password_list.append(result.group(5))


def get_most_common(search_list: list[any], results: int = 10):
    """Gets the most common results from a list

    Args:
        search_list: The list to parse
        results: The total results to return

    Returns:
        Dictionary with the results
    """
    out_dict = {
        "results": results,
    }
    for index, (value, count) in enumerate(Counter(search_list).most_common(results)):
        out_dict.update(
            {
                index: {
                    "value": value,
                    "count": count,
                }
            }
        )
    return out_dict


def main():
    """Main logic"""
    parser = argparse.ArgumentParser(prog="ssh honeypot scoreboard")
    parser.add_argument(
        "--honeypot-file",
        "-i",
        required=True,
        type=Path,
        help="The honeypot file to parse",
    )
    parser.add_argument(
        "--output-file", "-o", required=True, type=Path, help="The output file path"
    )
    args = parser.parse_args()

    date_list = []
    ip_list = []
    username_list = []
    password_list = []
    parse_honeypot_log(
        file_path=args.honeypot_file,
        date_list=date_list,
        ip_list=ip_list,
        username_list=username_list,
        password_list=password_list,
    )
    out_json = {
        "total_results": len(ip_list),
        "top_ips": get_most_common(ip_list),
        "top_usernames": get_most_common(username_list),
        "top_passwords": get_most_common(password_list),
    }
    with open(file=args.output_file, mode="w", encoding="utf-8") as output_file:
        json.dump(out_json, output_file)


if __name__ == "__main__":
    main()
