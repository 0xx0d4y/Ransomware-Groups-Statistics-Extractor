# Ransomware Groups Statistics Extractor

This Python tool interacts with the [ransomware.live API](https://ransomware.live/) to fetch and analyze victim data associated with ransomware groups. It aggregates victim data by month, providing statistics on total victims, affected sectors, and impacted countries (with a breakdown of sectors per country).

## Features

- **Data Collection:** Retrieves victim data from ransomware.live API.
- **Data Aggregation:** Groups data by month (formatted as `YYYY-MM`), counting:
  - Total number of victims.
  - Top 10 affected sectors.
  - Top 10 affected countries (with the top 3 sectors for each country).
- **Multiple Output Formats:**
  - **Normal:** Colorized terminal output (using Colorama).
  - **JSON:** Structured JSON output.
  - **CSV:** CSV output for further analysis.
- **Error Handling:** Gracefully manages API errors and file I/O exceptions.

## Prerequisites

- Python 3.6 or higher

## Installation

1. **Clone the Repository:**

   ```bash
   git clone https://github.com/0xx0d4y/Ransomware-Groups-Statistics-Extractor.git
   cd Ransomware-Groups-Statistics-Extractor
   ```

2. **Install Dependencies:**

It is recommended to use a virtual environment. Then run:

```bash
pip install -r requirements.txt
```

## Usage

Run the script from the command line with the following arguments:

- `--group` (required): The name of the ransomware group (e.g., lockbit, babuk2).
- `--format` (optional): Output format. Options:
    - `normal` (default): Colorized output for the terminal.
    - `json`: Outputs a JSON formatted string.
    - `csv`: Outputs data in CSV format.
- `--output` (optional): File path to save the output (for JSON and CSV). If omitted, the output is printed to the terminal.

### Usage Examples

- **Terminal (Normal) Output**:

```bash
python ransomware_group_statistics.py --group lockbit3
```

- **JSON Output to a File**:

```bash
python ransomware_group_statistics.py --group babuk2 --format json --output output.json
```

- **CSV Output Printed to Terminal**:

```bash
python ransomware_group_statistics.py --group lockbit --format csv
```

# To-Do

- In the future, I intend to add other integration options with APIs from other platforms that provide information about the activities of Ransomware Groups.
- Collect general information about the activities of Ransomware groups.
    - Option to collect which countries are most affected each month.
    - Option to collect which industries are most affected each month.
