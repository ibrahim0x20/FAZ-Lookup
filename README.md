# FAZ-Lookup

![FAZ-Lookup Screenshot](Capture.png)


FAZ-Lookup is a simple Fortinet FortiAnalyzer (FAZ) lookup tool that allows you to search and retrieve logs from FortiAnalyzer or a local SQLite database.

## Features

- Search logs from FortiAnalyzer or local SQLite database
- Support for multiple ADOM types (WAF, Proxy, Firewall)
- Various log types (traffic, app-ctrl, attack, content, event, history, virus, webfilter)
- Flexible query options
- Output in different formats (table, CSV, JSON)
- Background SQLite database updates

## Installation

1. Clone this repository:

git clone https://github.com/your-username/FAZ-Lookup.git

2. Install the required dependencies:

pip install -r requirements.txt

## Usage

python FAZ-Lookup.py [-h] -adom {waf,proxy,firewall} [-query QUERY] -st ST -et ET
[-r {table,csv,json}] [-v] [-logtype {traffic,app-ctrl,attack,content,event,history,virus,webfilter}]
[-sl SUSPECT_LIST] [-timeout TIMEOUT] [-fields] [-update-wl] [-update-db]

### Required Arguments

- `-adom {waf,proxy,firewall}`: Specify the ADOM type
- `-st ST`: Start time in "YYYY-MM-DD HH:MM" format
- `-et ET`: End time in "YYYY-MM-DD HH:MM" format

### Optional Arguments

- `-query QUERY`: Search query (optional)
- `-r {table,csv,json}`: Output format (default: table)
- `-v, --verbose`: Enable verbose output
- `-logtype {traffic,app-ctrl,attack,content,event,history,virus,webfilter}`: Log type (default: traffic)
- `-sl SUSPECT_LIST, --suspect-list SUSPECT_LIST`: Path to the suspicious srcip list JSON file
- `-timeout TIMEOUT`: Timeout for fetching data for a TID in seconds (default: 300)
- `-fields`: List fields available for the provided logtype
- `-update-wl`: Update white list URLs file
- `-update-db`: Update SQLite DB

## Query Format

The `-query` option accepts queries that comply with both FortiAnalyzer Filter syntax and SQLite syntax when searching the local database. This allows for flexible and powerful querying capabilities.

### Examples

1. Search for traffic logs in the firewall ADOM:

<code>python FAZ-Lookup.py -adom firewall -logtype traffic -st "2024-07-01 00:00" -et "2024-07-02 00:00" -query "srcip='192.168.1.100'"</code>

2. Retrieve application control logs from the proxy ADOM in JSON format:

<code>python FAZ-Lookup.py -adom proxy -logtype app-ctrl -st "2024-07-01 00:00" -et "2024-07-02 00:00" -r json</code>

3. Update the local SQLite database for WAF logs:

<code>python FAZ-Lookup.py -adom waf -logtype attack -st "2024-07-01 00:00" -et "2024-07-02 00:00" -update-db</code>

4. List available fields for traffic logs:

<code>python FAZ-Lookup.py -adom firewall -logtype traffic -fields</code>

5. Search for top visited URLs:

<code>python FAZ-Lookup.py -adom proxy -logtype traffic -st "2024-07-01 00:00" -et "2024-07-02 00:00" -query "TOP 10 http_url"</code>

## Note

- The tool first attempts to query the local SQLite database. If the requested data is not available locally or the time range is invalid, it will query the FortiAnalyzer directly.
- When updating the SQLite database (`-update-db`), the process runs in the background.
- The `-query` option supports both FortiAnalyzer Filter syntax and SQLite syntax, depending on whether the search is performed on FortiAnalyzer or the local SQLite database.

## Disclaimer

This tool is provided as-is, without any warranties. Use at your own risk.

## License

[MIT License](LICENSE)

## Author

Ibrahim Hakami - 1b0x1R