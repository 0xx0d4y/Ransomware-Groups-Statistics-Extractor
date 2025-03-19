import argparse
import csv
import json
import sys
import requests
from collections import defaultdict, Counter
from datetime import datetime
from colorama import Fore, Style, init

init(autoreset=True)

def get_victims_by_group(group_name):
    """
    Queries the ransomware.live API to return the victims associated with a group.
    The URI used was: /groupvictims/<group_name>
    """
    base_url = "https://api.ransomware.live/v2/groupvictims/"
    url = base_url + group_name
    try:
        response = requests.get(url, headers={"Accept": "application/json"})
        if response.status_code == 200:
            return response.json()
        else:
            print(f"Error: {response.status_code}")
            return []
    except Exception as e:
        print(f"An error occurred: {e}")
        return []

def process_victims(victims):
    """
    Processes the list of victims to group by month in the format: YYYY-MM.
    For each month, it will group:
      - Total victims.
      - Frequency of sectors (field 'activity').
      - Frequency of countries (field 'country').
      - For each country, groups the affected sectors.
    """
    monthly_data = defaultdict(lambda: {
        "total": 0,
        "sectors": Counter(),
        "countries": Counter(),
        "country_sectors": defaultdict(Counter)
    })
    
    for victim in victims:
        discovered = victim.get("discovered")
        if not discovered:
            continue
        try:
            dt = datetime.fromisoformat(discovered)
            month_key = dt.strftime("%Y-%m")
        except Exception:
            continue
        
        monthly_data[month_key]["total"] += 1
        sector = victim.get("activity") or "Not Identified"
        country = victim.get("country") or "Not Identified"
        
        monthly_data[month_key]["sectors"][sector] += 1
        monthly_data[month_key]["countries"][country] += 1
        monthly_data[month_key]["country_sectors"][country][sector] += 1
        
    return monthly_data

def print_monthly_summary(monthly_data):
    """
    Displays the grouped data by month in a colorful manner:
      - Total victims.
      - Top 10 sectors.
      - Top 10 countries and, for each country, the top 3 affected sectors.
    """
    if not monthly_data:
        print(f"{Fore.YELLOW}No data to display.{Style.RESET_ALL}")
        return

    for month in sorted(monthly_data):
        data = monthly_data[month]
        total = data["total"]
        top_sectors = data["sectors"].most_common(10)
        top_countries = data["countries"].most_common(10)
        
        print(f"\n{Fore.CYAN}Month: {month}{Style.RESET_ALL}")
        print(f"  {Fore.GREEN}Total victims: {total}{Style.RESET_ALL}")
        
        print(f"  {Fore.MAGENTA}Top sectors:")
        for sector, count in top_sectors:
            print(f"    - {sector}: {count}")
        
        print(f"  {Fore.BLUE}Top countries:")
        for country, count in top_countries:
            print(f"    - {country}: {count}")
            sectors_breakdown = data["country_sectors"][country].most_common(3)
            if sectors_breakdown:
                print(f"       {Fore.YELLOW}Affected sectors:")
                for sec, sec_count in sectors_breakdown:
                    print(f"         * {sec}: {sec_count}")
        print(Style.RESET_ALL)

def build_json_output(monthly_data):
    """
    Builds the JSON structure with the processed data for JSON output.
    """
    output = {}
    for month in sorted(monthly_data):
        data = monthly_data[month]
        top_sectors = data["sectors"].most_common(10)
        top_countries = data["countries"].most_common(10)
        countries_list = []
        for country, count in top_countries:
            sectors_breakdown = data["country_sectors"][country].most_common(3)
            top_country_sectors = [{"sector": sec, "count": sec_count} for sec, sec_count in sectors_breakdown]
            countries_list.append({
                "country": country,
                "count": count,
                "top_sectors": top_country_sectors
            })
        output[month] = {
            "total_victims": data["total"],
            "top_sectors": [{"sector": sector, "count": count} for sector, count in top_sectors],
            "top_countries": countries_list
        }
    return output

def write_csv_output(json_data, output_file=None):
    """
    Converts the output JSON into CSV format and writes it to a file (or prints to the terminal if output_file is not provided on the command line).
    Each line represents a month with the following columns:
      - Month
      - Total Victims
      - Top Sectors (format: "sector: count, ...")
      - Top Countries (format: "country (count): [sector: count, ...]; ...")
    """
    header = ["Month", "Total Victims", "Top Sectors", "Top Countries"]
    rows = []
    for month in sorted(json_data):
        summary = json_data[month]
        total_victims = summary["total_victims"]
        top_sectors = summary["top_sectors"]
        top_countries = summary["top_countries"]
        
        sectors_str = ", ".join(f"{item['sector']}: {item['count']}" for item in top_sectors)
        
        countries_list = []
        for country_info in top_countries:
            country = country_info["country"]
            count = country_info["count"]
            sectors = country_info["top_sectors"]
            sectors_detail = ", ".join(f"{s['sector']}: {s['count']}" for s in sectors)
            countries_list.append(f"{country} ({count}): [{sectors_detail}]")
        countries_str = "; ".join(countries_list)
        
        rows.append({
            "Month": month,
            "Total Victims": total_victims,
            "Top Sectors": sectors_str,
            "Top Countries": countries_str
        })
    
    if output_file:
        try:
            with open(output_file, "w", newline="", encoding="utf-8") as csvfile:
                writer = csv.DictWriter(csvfile, fieldnames=header)
                writer.writeheader()
                writer.writerows(rows)
            print(f"CSV output successfully saved to: {output_file}")
        except Exception as e:
            print(f"An error occurred while writing the CSV file: {e}")
    else:
        writer = csv.DictWriter(sys.stdout, fieldnames=header)
        writer.writeheader()
        writer.writerows(rows)

def main():
    parser = argparse.ArgumentParser(
        description="This script aims to extract information from the ransomware.live API about Ransomware Groups and their statistics."
    )
    parser.add_argument(
        "--group", required=True,
        help="Name of the malicious actor (e.g.: 'lockbit', 'babuk2')"
    )
    parser.add_argument(
        "--format", choices=["normal", "json", "csv"], default="normal",
        help="Output format: 'normal' for colored terminal output, 'json' for JSON, 'csv' for CSV."
    )
    parser.add_argument(
        "--output", default=None,
        help="File to save the output (valid for 'json' or 'csv' formats). If not provided, the output will be printed to the terminal."
    )
    args = parser.parse_args()
    
    group_name = args.group.strip().lower()
    print(f"Searching for victims for the group: {group_name} ...")
    
    victims = get_victims_by_group(group_name)
    if not victims:
        print("No victims found or an error occurred when querying the ransomware.live API. Is it DOWN?")
        return

    monthly_data = process_victims(victims)
    
    if args.format == "normal":
        print_monthly_summary(monthly_data)
    elif args.format == "json":
        output_json = build_json_output(monthly_data)
        json_string = json.dumps(output_json, indent=4, ensure_ascii=False)
        if args.output:
            try:
                with open(args.output, "w", encoding="utf-8") as f:
                    f.write(json_string)
                print(f"JSON output successfully saved to file: {args.output}")
            except Exception as e:
                print(f"An error occurred while writing the JSON file: {e}")
        else:
            print(json_string)
    elif args.format == "csv":
        output_json = build_json_output(monthly_data)
        write_csv_output(output_json, args.output)

if __name__ == "__main__":
    main()
