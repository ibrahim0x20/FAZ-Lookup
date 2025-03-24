import os.path
import time
from typing import List, Dict, Any, Optional, Union, Tuple
from contextlib import closing
from typing import Any, List
import sqlite3
import sys
import traceback
import json

from hadi_logger import get_logger

logger = get_logger()


class SQLiteManager:
    """A modular SQLite database manager that can handle any database and table structure."""

    def __init__(self, db_path: str):
        """
        Initialize the SQLite database manager.

        Args:
            db_path: Path to the SQLite database file
        """
        # self.logger = setup_logging(os.path.join("logs", "hadi-ir.log"), __name__)
        self.db_path = db_path
        self.conn = None
        self.conn = None
        self.connRAW = None
        self.reindex = False
        self.indexList = []

        # If file exists, check it's our DB schema
        if os.path.isfile(self.db_path):
            test_conn = sqlite3.connect(self.db_path, timeout=10)
            with closing(test_conn.cursor()) as cursor:
                try:
                    cursor.execute("SELECT name, type, sql FROM sqlite_master WHERE type='table';")
                    schema_info = cursor.fetchall()
                    # todo Add table for version to check if the database is compatible.
                    # for row in schema_info:
                    #     print(row)
                    return
                except sqlite3.OperationalError as error:
                    logger.log("DEBUG", "DB is not compatible: %s" % self.db_path)
                    # todo exit, not our db schema don't touch it.
                    return

                # todo: Detect empty leftover DB's and handle them gracefully
                # # Check if its a valid DB or leftover from failed load attempt
                # # Count entries
                # c.execute("SELECT count(*) FROM Entries")
                # entries_count = c.fetchone()[0]
                # if entries_count == 0:
                #     os.remove(self.dbfilenameFullPath)

    # Override the existing __del__ and close methods to include index handling
    def __del__(self):
        if self.reindex and self.conn:
            self.add_indexes()
        if self.conn is not None:
            self.conn.close()
        if self.connRAW is not None:
            self.connRAW.close()

    def close(self, *err):
        if self.reindex and self.conn:
            self.add_indexes()
        if self.conn is not None:
            self.conn.close()
        if self.connRAW is not None:
            self.connRAW.close()

    def __enter__(self, *err):
        return self

    def __exit__(self, *err):
        self.close()

    def __call__(self):
        return 0

    def connectDB(self, db_path=None):
        """Initialize the database connection with optimizations."""

        if db_path is not None:
            self.db_path = db_path
        if os.path.isfile(self.db_path):
            try:
                self.conn = sqlite3.connect(
                    self.db_path,
                    check_same_thread=False,  # Allow usage across threads
                    timeout=20,  # Increase timeout for busy database
                    detect_types=sqlite3.PARSE_DECLTYPES | sqlite3.PARSE_COLNAMES
                )
                cursor = self.conn.cursor()
                self._apply_optimizations(cursor)
                logger.log("INFO", "Database connection initialized successfully")
            except sqlite3.Error as e:
                logger.log("ERROR", f"Error initializing database connection: {self.db_path} {str(e)}")
                raise
        else:
            logger.log("ERROR", "Sqlite DB not found!")
            raise ValueError('Sqlite DB not found!')
        return self.conn

    def _get_cursor(self) -> sqlite3.Cursor:
        """Get a cursor from the existing connection, reinitializing if necessary."""
        if self.conn is not None:
            return self.conn.cursor()
        else:
            logger.log("ERROR", "No active connection exsits!")
            raise ValueError('No active connection exsits!')

    @staticmethod
    def _apply_optimizations(cursor: sqlite3.Cursor) -> None:
        """Apply SQLite optimizations for better performance."""
        optimizations = [
            # 'PRAGMA journal_mode = WAL',
            # 'PRAGMA synchronous = NORMAL',
            'PRAGMA journal_mode = OFF',
            'PRAGMA synchronous = OFF',
            'PRAGMA cache_size = 1000000',
            'PRAGMA locking_mode = EXCLUSIVE',
            'PRAGMA temp_store = MEMORY',
            'PRAGMA busy_timeout = 60000'  # Set busy timeout to 60 seconds
        ]
        for opt in optimizations:
            cursor.execute(opt)

    def _cleanup(self) -> None:
        """Cleanup database connections on program exit."""
        try:
            with self._connection_lock:
                if self._connection:
                    self._connection.close()
                    self._connection = None
                    logger.log("INFO", "Database connection closed successfully")
        except sqlite3.Error as e:
            logger.log("ERROR", f"Error during database cleanup: {str(e)}")

    def create_table(self, table_name: str, fields: Dict[str, str],
                     unique_id_field: Optional[str] = 'id') -> bool:
        """
        Create a new table if it doesn't exist.

        Args:
            table_name: Name of the table to create
            fields: Dictionary of field names and their SQL types
            unique_id_field: Name of the unique ID field (default: 'id').
                           Set to None to create table without unique ID.

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            cursor = self._get_cursor()

            # Create a copy of fields to avoid modifying the input dictionary
            table_fields = fields.copy()

            # Handle unique ID field if specified
            if unique_id_field:
                if unique_id_field in table_fields:
                    # If the field exists, modify it to be the primary key
                    table_fields[unique_id_field] += ' PRIMARY KEY'
                else:
                    # Add the unique ID field if it doesn't exist
                    table_fields[unique_id_field] = 'INTEGER PRIMARY KEY'

            field_definitions = [
                f"{field} {dtype}" for field, dtype in table_fields.items()
            ]
            create_table_sql = f"""
            CREATE TABLE IF NOT EXISTS {table_name} (
                {', '.join(field_definitions)}
            )
            """
            cursor.execute(create_table_sql)
            self._connection.commit()
            return True
        except sqlite3.Error as e:
            logger.log("ERROR", f"Error creating table {table_name}: {str(e)}")
            return False

    def insert_data(self, table_name: str, data: List[Dict[str, Any]],
                    batch_size: int = 50) -> bool:
        """
        Insert data into the specified table.

        Args:
            table_name: Name of the table to insert into
            data: List of dictionaries containing the data to insert
            batch_size: Number of records to insert in each batch

        Returns:
            bool: True if successful, False otherwise
        """
        if not data:
            logger.log("WARNING", "No data provided for insertion")
            return False

        try:
            cursor = self._get_cursor()

            # Get field names from the first record
            fields = list(data[0].keys())

            # Prepare the INSERT statement
            placeholders = ', '.join(['?' for _ in fields])
            columns = ', '.join(fields)
            sql = f'INSERT OR REPLACE INTO {table_name} ({columns}) VALUES ({placeholders})'

            # Insert data in batches
            for i in range(0, len(data), batch_size):
                batch = data[i:i + batch_size]
                values = [[record.get(field, None) for field in fields]
                          for record in batch]
                cursor.executemany(sql, values)
                self._connection.commit()

            return True
        except sqlite3.Error as e:
            logger.log("ERROR", f"Error inserting data into {table_name}: {str(e)}")
            if self._connection:
                self._connection.rollback()
            return False

    def Query(self, query: str) -> List[Any]:
        """
        Execute a SQL query and return the results.

        Args:
            query (str): The SQL query to execute

        Returns:
            List[Any]: The query results

        Raises:
            Exception: If the query fails with formatted error message
        """
        try:
            with closing(self.conn.cursor()) as c:
                c.execute(query)
                data = c.fetchall()
                return data
        except sqlite3.Error as e:
            error_msg = f"SQLITE error: {str(e)} [Query: {query}]"
            logger.exception(error_msg)
            traceback.print_exc(file=sys.stdout)
            raise Exception(error_msg)
        except Exception as e:
            error_msg = f"Unexpected error: {str(e)} [Query: {query}]"
            logger.exception(error_msg)
            traceback.print_exc(file=sys.stdout)
            raise

    def query_data(self, query: str) -> List[Dict[str, Any]]:
        """
        Execute a query on the specified table.

        Args:
            query: Complete SQL query string

        Returns:
            List of dictionaries containing the query results
        """
        table_name = query.split(' FROM ')[1]
        try:
            cursor = self._get_cursor()
            cursor.execute(query)

            # Get column names and return results as dictionaries
            columns = [description[0] for description in cursor.description]
            results = [dict(zip(columns, row)) for row in cursor.fetchall()]

            return results

        except sqlite3.Error as e:
            logger.log("ERROR", f"Error querying data from {table_name}: {str(e)}")
            return []

    def is_table_empty(self, table_name: str) -> bool:
        """
        Check if a specific table is empty.

        Args:
            table_name: Name of the table to check

        Returns:
            True if the table is empty, False otherwise
        """
        query = f"SELECT COUNT(*) FROM {table_name}"
        try:
            cursor = self._get_cursor()
            cursor.execute(query)
            result = cursor.fetchone()[0]  # `result` will hold the count as an integer

            return result == 0  # True if empty, False otherwise

        except sqlite3.Error as e:
            logger.log("ERROR", f"Failed to check if {table_name} is empty: {str(e)}")
            return False

    def delete_old_records(self, table_name: str, timestamp_field: str,
                           days_to_keep: int) -> bool:
        """
        Delete records older than the specified number of days.

        Args:
            table_name: Name of the table to clean up
            timestamp_field: Name of the timestamp field
            days_to_keep: Number of days of data to retain

        Returns:
            bool: True if successful, False otherwise
        """
        try:
            cursor = self._get_cursor()
            threshold = int(time.time()) - (days_to_keep * 24 * 60 * 60)

            delete_query = f"""
            DELETE FROM {table_name} 
            WHERE {timestamp_field} < ?
            """

            cursor.execute(delete_query, (threshold,))
            deleted_count = cursor.rowcount
            self._connection.commit()

            self.logger.log("INFO",
                            f"Deleted {deleted_count} records older than {days_to_keep} days "
                            f"from {table_name}"
                            )
            return True
        except sqlite3.Error as e:
            logger.log("ERROR", f"Error deleting old records from {table_name}: {str(e)}")
            if self._connection:
                self._connection.rollback()
            return False

    def table_exists(self, table_name: str) -> bool:
        """Check if a table exists in the database."""
        try:
            cursor = self._get_cursor()
            cursor.execute(
                "SELECT name FROM sqlite_master WHERE type='table' AND name=?",
                (table_name,)
            )
            return cursor.fetchone() is not None
        except sqlite3.Error as e:
            logger.log("ERROR", f"Error checking table existence: {str(e)}")
            return False

    def getFields(self) -> Dict[str, List[str]]:
        """
        Get all tables in the database and their fields.

        Returns:
            Dict[str, List[str]]: Dictionary mapping table names to their field lists
            Format: {'table_name': ['field1', 'field2', ...], ...}
        """
        try:
            # Get a cursor from the connection
            cursor = self._get_cursor()
            # Get all table names
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [row[0] for row in cursor.fetchall()]

            # Get fields for each table
            result = {}
            for table_name in tables:
                data = cursor.execute(f"SELECT * FROM {table_name} LIMIT 1")
                fields = [description[0] for description in data.description]
                result[table_name] = fields

            return result
        except sqlite3.Error as e:
            logger.log("ERROR", f"Error getting table fields: {str(e)}")
            return {}

    def CountEntries(self, table):
        with closing(self.conn.cursor()) as c:
            c.execute(f"SELECT count(*) FROM {table}")
            count = c.fetchone()[0]
        return count

    def set_index_flag(self) -> None:
        """Set the flag to indicate that reindexing is needed."""
        self.reindex = True

    def check_index_exists(self, index_name: str) -> bool:
        """
        Check if a specific index exists in the database.

        Args:
            index_name: Name of the index to check

        Returns:
            bool: True if index exists, False otherwise
        """
        try:
            with closing(self._get_cursor()) as cursor:
                cursor.execute(
                    "SELECT name FROM sqlite_master WHERE type='index' AND name=?",
                    (index_name,)
                )
                return cursor.fetchone() is not None
        except sqlite3.Error as e:
            logger.log("ERROR", f"Error checking index {index_name}: {str(e)}")
            return False

    def load_indexes(self) -> None:
        """
        Load existing indexes for all tables into indexList.
        Only loads indexes that start with 'index_'.
        """
        try:
            with closing(self._get_cursor()) as cursor:
                cursor.execute(
                    "SELECT name FROM sqlite_master WHERE type='index' AND name LIKE 'index_%'"
                )
                rows = cursor.fetchall()
                if rows:
                    self.reindex = False
                    self.indexList = [row[0] for row in rows]
                else:
                    self.indexList = []
        except sqlite3.Error as e:
            logger.log("ERROR", f"Error loading indexes: {str(e)}")
            self.indexList = []

    def is_field_indexed(self, field_name: str) -> bool:
        """
        Check if a specific field is indexed.

        Args:
            field_name: Name of the field to check

        Returns:
            bool: True if field is indexed, False otherwise
        """
        return any(field_name in index for index in self.indexList)

    def add_indexes(self) -> bool:
        """
        Add indexes to the database if reindex flag is set.

        Returns:
            bool: True if successful, False otherwise
        """
        if not self.reindex or not self.conn:
            return False

        try:
            with closing(self._get_cursor()) as cursor:
                # Example index creation - customize based on your needs
                # Add your specific index creation queries here
                # cursor.execute("CREATE INDEX IF NOT EXISTS index_table_field ON table(field)")
                self.conn.commit()
                self.reindex = False
                logger.log("INFO", "Database indexes added successfully")
                self.load_indexes()  # Refresh index list
                return True
        except sqlite3.Error as e:
            logger.log("ERROR", f"Error adding indexes: {str(e)}")
            self.conn.rollback()
            return False

    def require_index(self, index_name: str, index_query: str, quiet: bool = False) -> bool:
        """
        Ensure a required index exists, creating it if necessary.

        Args:
            index_name: Name of the index to check/create
            index_query: SQL query to create the index
            quiet: If True, suppress logging of index creation

        Returns:
            bool: True if index exists or was created successfully, False otherwise
        """
        if self.check_index_exists(index_name):
            return True

        if not quiet:
            logger.log("INFO", f"Creating required index: {index_name}")

        try:
            with closing(self._get_cursor()) as cursor:
                cursor.execute(index_query)
                self.conn.commit()
                self.indexList.append(index_name)
                logger.log("INFO", f"Index {index_name} created successfully")
                return True
        except sqlite3.Error as e:
            logger.log("ERROR", f"Error creating index {index_name}: {str(e)}")
            self.conn.rollback()
            return False

    def drop_indexes(self) -> bool:
        """
        Drop all tracked indexes from the database.

        Returns:
            bool: True if successful, False otherwise
        """
        if not self.indexList or not self.conn:
            return False

        try:
            with closing(self._get_cursor()) as cursor:
                for index in self.indexList:
                    cursor.execute(f"DROP INDEX IF EXISTS {index}")
                self.conn.commit()
                logger.log("INFO", "All tracked indexes dropped successfully")
                self.indexList = []
                self.reindex = True
                return True
        except sqlite3.Error as e:
            logger.log("ERROR", f"Error dropping indexes: {str(e)}")
            self.conn.rollback()
            return False

    def get_status(self) -> Dict[str, Any]:
        """
        Get basic information on the status of the current session.

        Returns:
            dict: Dictionary containing status information
        """
        status = {
            "database_path": self.db_path,
            "connection_active": self.conn is not None,
            "index_count": len(self.indexList),
            "indexes": self.indexList.copy(),
            "reindex_needed": self.reindex,
            "file_exists": os.path.isfile(self.db_path)
        }
        return status

    def describe_database(self):
        # Connect to database and get cursor
        cursor = self._get_cursor()

        # Get all table names
        cursor.execute("SELECT name FROM sqlite_master WHERE type IN ('table', 'view');")
        tables = cursor.fetchall()

        # Create dictionary to store database structure
        db_structure = {}

        for table in tables:
            table_name = table[0]

            # Skip system tables
            if table_name.startswith('sqlite_'):
                continue

            # Initialize table info dictionary
            table_info = {}

            # Get column information
            cursor.execute(f"PRAGMA table_info('{table_name}');")
            columns = cursor.fetchall()
            column_names = [col[1] for col in columns]

            # Get first row of data and combine with column names
            cursor.execute(f"SELECT * FROM {table_name} LIMIT 1;")
            first_row = cursor.fetchone()
            if first_row:
                table_info['columns'] = {
                    column_names[i]: str(val) if val is not None else None
                    for i, val in enumerate(first_row)
                }

            # Get index information
            cursor.execute(f"PRAGMA index_list('{table_name}');")
            indexes = cursor.fetchall()
            if indexes:
                table_info['indexes'] = [
                    {
                        'name': index[1],
                        'unique': bool(index[2])
                    } for index in indexes
                ]

            # Add table info to main structure
            db_structure[table_name] = table_info

        # Print as formatted JSON
        print(json.dumps(db_structure, indent=2))

        return db_structure  # Optional: return the structure if needed

    # Example usage:
    # db = SomeDatabaseClass()
    # db.describe_database()


class CreateViewTable:
    def __init__(self, db_path, search_term, search_column="FileName"):
        self.db_path = db_path
        self.search_term = search_term
        self.search_column = search_column
        self.first_table = None
        self.second_table = None
        self.view_name = None
        self.check_database_locks()  # Run lock check before proceeding
        self._initialize_search()

    def check_database_locks(self):
        """Check if the database is locked; exit with error if it is."""
        try:
            with sqlite3.connect(self.db_path, timeout=10) as conn:
                cursor = conn.cursor()
                cursor.execute("BEGIN IMMEDIATE TRANSACTION")
                logger.debug("No locks detected, transaction started successfully")
                conn.rollback()  # Roll back since this is just a test
        except sqlite3.OperationalError as e:
            logger.error(f"Database is locked: {e}. Cannot create view table.")
            logger.error("To resolve this, find where the database is connected and close it:")
            logger.error(f"- Check your code for unclosed sqlite3 connections to '{self.db_path}'.")
            logger.error("- Look for uncommitted transactions (e.g., BEGIN without COMMIT/ROLLBACK).")
            logger.error("- If using multiple processes/threads, ensure proper synchronization.")
            logger.error("Exiting program due to database lock.")
            sys.exit(1)  # Exit the program with an error code

    def _get_columns(self, table_name):
        """Get all column names for a given table."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute(f"PRAGMA table_info({table_name});")
            return [row[1] for row in cursor.fetchall()]

    def _find_tables_with_column(self, column_name):
        """Find all tables containing a specific column."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [row[0] for row in cursor.fetchall()]
            return [t for t in tables if column_name in self._get_columns(t)]

    def _search_column(self):
        """Search for the term in the specified column (e.g., FileName)."""
        tables = self._find_tables_with_column(self.search_column)
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            for table in tables:
                query = f"SELECT * FROM {table} WHERE {self.search_column} = ? LIMIT 1"
                cursor.execute(query, (self.search_term,))
                result = cursor.fetchone()
                if result:
                    self.first_table = table
                    return table, result
        return None, None

    def _find_second_table_with_term(self, exclude_table, exclude_column):
        """Find a second table where the search term appears in any column."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            tables = [row[0] for row in cursor.fetchall()]
            for table in tables:
                if table == exclude_table:
                    continue
                columns = self._get_columns(table)
                for column in columns:
                    if column == exclude_column:
                        continue
                    query = f"SELECT * FROM {table} WHERE {column} LIKE ? LIMIT 1"
                    try:
                        cursor.execute(query, (f"%{self.search_term}%",))
                        result = cursor.fetchone()
                        if result:
                            return table, column, result
                    except sqlite3.Error:
                        continue
        return None, None, None

    def _find_tables_with_common_column(self, first_table):
        """Find all tables with a common column to the first table."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            all_tables = [row[0] for row in cursor.fetchall()]
            first_cols = set(self._get_columns(first_table))
            matching_tables = []
            for table in all_tables:
                if table == first_table:
                    continue
                other_cols = set(self._get_columns(table))
                common_cols = first_cols.intersection(other_cols)
                if common_cols:
                    matching_tables.append((table, list(common_cols)[0]))
            return matching_tables if matching_tables else None

    def _find_common_columns(self, table1, table2):
        """Find common columns between two tables."""
        cols1 = set(self._get_columns(table1))
        cols2 = set(self._get_columns(table2))
        return cols1.intersection(cols2)

    def _create_view(self, table1, table2, common_column):
        """Create a view joining two tables without duplicating the common column."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            t1_cols = self._get_columns(table1)
            t2_cols = self._get_columns(table2)
            select_cols = [f"{table1}.{col} AS {col}" if col == common_column else f"{table1}.{col}" for col in t1_cols]
            select_cols.extend(f"{table2}.{col}" for col in t2_cols if col != common_column)
            self.view_name = f"{table1}_{table2}"
            query = f"""
                CREATE VIEW IF NOT EXISTS {self.view_name} AS
                SELECT {', '.join(select_cols)}
                FROM {table1}
                INNER JOIN {table2} ON {table1}.{common_column} = {table2}.{common_column}
            """
            cursor.execute(query)
            conn.commit()

    def _find_indirect_relationship(self, table1, table2):
        """Find an intermediate table for an indirect join."""
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            cursor.execute("SELECT name FROM sqlite_master WHERE type='table';")
            all_tables = [row[0] for row in cursor.fetchall()]
            for intermediate in all_tables:
                if intermediate in (table1, table2):
                    continue
                cols1 = self._find_common_columns(table1, intermediate)
                cols2 = self._find_common_columns(intermediate, table2)
                if cols1 and cols2:
                    return intermediate, list(cols1)[0], list(cols2)[0]
        return None, None, None

    def _initialize_search(self):
        """Initialize the search and view creation process."""
        self.first_table, first_row = self._search_column()
        if not self.first_table:
            print(f"'{self.search_term}' not found in any {self.search_column} column")
            return

        self.second_table, second_col, second_row = self._find_second_table_with_term(self.first_table,
                                                                                      self.search_column)
        if self.second_table:
            print(f"Second hit found in '{self.second_table}.{second_col}'")
        else:
            print(f"No second table found with '{self.search_term}', searching for common columns...")
            matching_tables = self._find_tables_with_common_column(self.first_table)
            if not matching_tables:
                print(f"No tables found with a common column to '{self.first_table}'")
                return
            print(f"Found tables with common columns to '{self.first_table}':")
            for i, (table, col) in enumerate(matching_tables, 1):
                print(f"{i}. {table} (common column: {col})")
            while True:
                try:
                    choice = int(input("Select a table by number: "))
                    if 1 <= choice <= len(matching_tables):
                        self.second_table, common_col = matching_tables[choice - 1]
                        print(f"Selected: '{self.second_table}' with common column '{common_col}'")
                        break
                    print(f"Enter a number between 1 and {len(matching_tables)}")
                except ValueError:
                    print("Please enter a valid number")

        common_cols = self._find_common_columns(self.first_table, self.second_table)
        if common_cols:
            self._create_view(self.first_table, self.second_table, list(common_cols)[0])
            print(f"View created: {self.view_name}")
        else:
            intermediate, key1, key2 = self._find_indirect_relationship(self.first_table, self.second_table)
            if intermediate:
                self.view_name = f"{self.first_table}_{intermediate}_{self.second_table}_View"
                with sqlite3.connect(self.db_path) as conn:
                    cursor = conn.cursor()
                    query = f"""
                        CREATE VIEW IF NOT EXISTS {self.view_name} AS
                        SELECT * FROM {self.first_table}
                        INNER JOIN {intermediate} ON {self.first_table}.{key1} = {intermediate}.{key1}
                        INNER JOIN {self.second_table} ON {intermediate}.{key2} = {self.second_table}.{key2}
                    """
                    cursor.execute(query)
                    conn.commit()
                print(f"Indirect view created: {self.view_name}")
            else:
                print("No direct or indirect relationship found")

    def get_view_data(self, limit=10):
        """Retrieve data from the created view."""
        if not self.view_name:
            print("No view has been created yet.")
            return None
        with sqlite3.connect(self.db_path) as conn:
            cursor = conn.cursor()
            # Get the columns in the view to verify search_column exists
            cursor.execute(f"PRAGMA table_info({self.view_name});")
            view_columns = [row[1] for row in cursor.fetchall()]

            if self.search_column not in view_columns:
                print(f"Column '{self.search_column}' not found in view '{self.view_name}'")
                return None

            # Use the column name without table prefix since it's in the view's namespace
            query = f"SELECT * FROM {self.view_name} WHERE {self.search_column} = ? LIMIT ?"
            cursor.execute(query, (self.search_term, limit))
            return cursor.fetchall()