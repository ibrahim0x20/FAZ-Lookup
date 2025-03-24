# update_SQLiteDB.py
import sys
import os
import FAZsqlite  # Adjust this import as needed
import ast
import argparse
import json
import logging
import progress
import time
import sqlite3

# Configure logging to output to both console and file
logging.basicConfig(filename='FAZlogs/update.log', filemode='a',
                    format='%(asctime)s - %(levelname)s - %(message)s', level=logging.INFO)

def remove_lock(devtype):
    LOCK_FILE = f"{devtype}.lock"
    if os.path.exists(LOCK_FILE):
        os.remove(LOCK_FILE)


def process_log_files(devtype):
    
    try:
        start_time = time.time() 
            
        FAZsqlite.execute_regular_search()
        print("Child process has finished.")
        end_time = time.time()
        logging.info(f"Time taken to update SQLite DB: {end_time - start_time} seconds")
        
    finally:
        remove_lock(devtype)
        
    # return processed_files
    

def get_hourly_logs(db_path, logtype):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()
        query = f"""
        SELECT DISTINCT 
            strftime('%Y-%m-%d %H:00', itime) AS hour_start
        FROM 
            {logtype}
        WHERE 
            strftime('%M', itime) = '00'
        ORDER BY 
            hour_start;
        """
        cursor.execute(query)
        results = cursor.fetchall()
        conn.close()
        hourly_logs = [datetime.strptime(row[0], '%Y-%m-%d %H:%M') for row in results]
        return hourly_logs
    except sqlite3.Error as e:
        logging.warning(f"An error occurred: {e}")
        return None

def create_and_populate_timeline(db_path, logtype):
    try:
        conn = sqlite3.connect(db_path)
        cursor = conn.cursor()

        # Create the timeline table for the specific logtype if it doesn't exist
        cursor.execute(f'''
        CREATE TABLE IF NOT EXISTS {logtype}_timeline (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hour_start TEXT UNIQUE
        )
        ''')

        # Get the hourly logs
        hourly_logs = get_hourly_logs(db_path, logtype)

        # Insert the hourly logs into the timeline table
        for log in hourly_logs:
            cursor.execute(f'''
            INSERT OR IGNORE INTO {logtype}_timeline (hour_start)
            VALUES (?)
            ''', (log.strftime('%Y-%m-%d %H:%M'),))

        conn.commit()
        conn.close()

        logging.info(f"{logtype}_timeline table created and populated")

    except sqlite3.Error as e:
        logging.warning(f"An error occurred: {e}")
    
def main():
    args_json = sys.argv[1]  # Collect command-line argument as string
    fields_json = sys.argv[2]  # Collect command-line argument as string
    devtype = sys.argv[3]
    # Deserialize the JSON string back into a dictionary
    args_dict = json.loads(args_json)
    fields = json.loads(fields_json)
    # Create a Namespace object from the dictionary
    args_namespace = argparse.Namespace(**args_dict)
      # Log an info message
    # logging.info(f"Processing files with arguments: {args_namespace} and fields: {fields}")
    
    try:
        
        FAZsqlite.FAZsqlite(args_namespace)
        fetchlogs.init(args_namespace)
        # Your existing code here
    except Exception as e:
        logging.error(f"An unexpected error occurred: {e}")
        return

    db_path = os.path.join('FAZlogs', f'{devtype}.db')
    if args_namespace.update_wl and args_namespace.adom == 'waf':
        
        logging.info(f"Updating WhiteListURLs, and cleaning {devtype}.db SQLit database.")
        conn = FAZsqlite.get_db_connection(db_path)
        conn = FAZsqlite.top_http_url(conn, devtype, args_namespace.logtype)
        return
    
    args_namespace.query = "!((dstip='172.16.0.0/12' and srcip='10.0.0.0/8') or (srcip='172.16.0.0/12' and dstip='10.0.0.0/8') or (srcip='10.0.0.0/8' and dstip='10.0.0.0/8') or (srcip='172.16.0.0/12' and dstip='172.16.0.0/12'))"        
    process_log_files(devtype)
    
    # Create and populate the timeline table
    create_and_populate_timeline(db_path, args_namespace.logtype)

if __name__ == "__main__":
    main()