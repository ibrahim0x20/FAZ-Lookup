import json
import re
import sys
import logging
import asyncio
import aiohttp
from collections import defaultdict
from typing import Dict, List, Any, Optional

# Configure logging
logger = logging.getLogger(__name__)


class DataFieldAnalyzer:
    def __init__(self, fields=None, search_request_func=None):
        """
        Initialize the analyzer with optional fields list and search request function.

        Args:
            fields (list, optional): List of fields to analyze
            search_request_func (callable, optional): Function to make search requests
        """
        self.fields = fields if fields else []
        self.search_request = search_request_func

    async def search_request_status(self, session, tid):
        """
        Placeholder method for getting search request status.
        This should be implemented based on your actual API.
        """
        # Implement based on your actual API
        pass

    def close_tid(self, tid):
        """
        Placeholder method for closing a search request.
        This should be implemented based on your actual API.
        """
        # Implement based on your actual API
        pass

    def _is_timestamp(self, field, value):
        """
        Helper method to detect if a string looks like a timestamp.

        Args:
            field (str): Field name
            value (str): Field value to check

        Returns:
            bool: True if the value appears to be a timestamp
        """
        # Timestamp patterns
        timestamp_patterns = [
            r'\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}',  # ISO format
            r'\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2}',  # Common datetime format
            r'\d{2}/\d{2}/\d{4} \d{2}:\d{2}:\d{2}',  # MM/DD/YYYY format
            r'\d{4}-\d{2}-\d{2}'  # Date only format
        ]

        # Check all patterns
        for pattern in timestamp_patterns:
            if re.match(pattern, str(value)):
                return True

        # Additional checks for timestamp-specific fields
        time_field_names = ['date', 'time', 'itime', 'dtime', 'eventtime', 'itime_t', 'timestamp', 'created_at',
                            'updated_at']
        if field.lower() in time_field_names or 'time' in field.lower() or 'date' in field.lower():
            # Additional validation for numeric timestamps
            try:
                num_val = int(value)
                # Check for unix timestamp ranges (reasonable range)
                if 1000000000 <= num_val <= 9999999999:  # Seconds since epoch (2001-2286)
                    return True
                if 1000000000000 <= num_val <= 9999999999999:  # Milliseconds since epoch
                    return True
            except (ValueError, TypeError):
                pass

        return False

    async def detect_field_types(self, data: List[Dict[str, Any]], retry_count=0, max_retries=3) -> Dict[str, str]:
        """
        Detect field types from the provided data with retry logic.

        Args:
            data (list): List of dictionaries containing records
            retry_count (int): Current retry attempt
            max_retries (int): Maximum number of retry attempts

        Returns:
            Dict[str, str]: Dictionary mapping field names to their detected types
        """
        if retry_count >= max_retries:
            logger.error(f"Failed to determine field types after {max_retries} attempts")
            return {}

        try:
            # Get all field names if not specified
            all_fields = set()
            for record in data:
                all_fields.update(record.keys())

            # Use specified fields or all fields
            fields_to_check = self.fields if self.fields else list(all_fields)

            # Initialize fields_types with TEXT as default
            fields_types = {field: "TEXT" for field in fields_to_check}

            # Process each item to determine types
            for item in data:
                for field in fields_to_check:
                    if field in item and item[field] is not None:
                        value = item[field]

                        if isinstance(value, int) or (isinstance(value, str) and
                                                      (value.isdigit() or (
                                                              value.startswith('-') and value[1:].isdigit()))):
                            detected_type = "INTEGER"
                        elif isinstance(value, float) or (isinstance(value, str) and re.match(r'^-?\d+\.\d+$', value)):
                            detected_type = "DECIMAL"
                        elif self._is_timestamp(field, value):
                            detected_type = "TIMESTAMP"
                        elif isinstance(value, str) and re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$', value):
                            detected_type = "VARCHAR_IP"  # Special case for IP addresses
                        else:
                            detected_type = "VARCHAR"

                        # Update with priority: TIMESTAMP > DECIMAL > INTEGER > VARCHAR_IP > VARCHAR
                        if detected_type == "TIMESTAMP":
                            fields_types[field] = "TIMESTAMP"
                        elif detected_type == "DECIMAL" and fields_types[field] not in ["TIMESTAMP"]:
                            fields_types[field] = "DECIMAL"
                        elif detected_type == "INTEGER" and fields_types[field] not in ["TIMESTAMP", "DECIMAL"]:
                            fields_types[field] = "INTEGER"
                        elif detected_type == "VARCHAR_IP" and fields_types[field] not in ["TIMESTAMP", "DECIMAL",
                                                                                           "INTEGER"]:
                            fields_types[field] = "VARCHAR_IP"

            return fields_types

        except Exception as e:
            logger.error(f"Failed to determine field types: {str(e)}")
            # Implement retry logic
            return await self.detect_field_types(data, retry_count + 1, max_retries)

    async def identify_primary_key(self, data: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Analyzes data to identify potential primary key fields with improved logic.

        Args:
            data (list): List of dictionaries containing records

        Returns:
            dict: Dictionary of potential primary key fields and their uniqueness stats
        """
        if not data:
            return {"error": "No data provided"}

        # Get all field names from the first record
        all_fields = set(data[0].keys())

        # Check if all records have the same fields
        for record in data:
            if set(record.keys()) != all_fields:
                logger.warning("Not all records have the same fields")
                all_fields = all_fields.union(set(record.keys()))

        # Count occurrences of each value for each field
        field_values = defaultdict(set)
        field_null_count = defaultdict(int)

        # Track if values are monotonically increasing/decreasing for each field
        prev_values = {}
        is_first_record = {}
        monotonic_increasing = {}
        monotonic_decreasing = {}

        # Get field types asynchronously
        field_types = await self.detect_field_types(data)

        # Analyze each field
        for record in data:
            for field in all_fields:
                if field in record:
                    if record[field] is None:
                        field_null_count[field] += 1
                    else:
                        value = str(record[field])
                        field_values[field].add(value)

                        # Check if field values are monotonically increasing or decreasing
                        if field_types.get(field) in ['INTEGER', 'DECIMAL', 'VARCHAR']:
                            if field not in is_first_record:
                                is_first_record[field] = True
                                prev_values[field] = value
                                monotonic_increasing[field] = True
                                monotonic_decreasing[field] = True
                            else:
                                try:
                                    # Handle large integer strings that might exceed normal int range
                                    if field_types.get(field) == 'INTEGER' and value.isdigit() and prev_values[field].isdigit():
                                        curr_val = int(value)
                                        prev_val = int(prev_values[field])
                                    else:
                                        curr_val = float(value) if '.' in value else int(value)
                                        prev_val = float(prev_values[field]) if '.' in prev_values[field] else int(prev_values[field])

                                    # Update monotonic status
                                    if curr_val <= prev_val:
                                        monotonic_increasing[field] = False
                                    if curr_val >= prev_val:
                                        monotonic_decreasing[field] = False

                                    prev_values[field] = value
                                except (ValueError, TypeError):
                                    # If we cannot convert to numbers, compare strings
                                    if value <= prev_values[field]:
                                        monotonic_increasing[field] = False
                                    if value >= prev_values[field]:
                                        monotonic_decreasing[field] = False
                                    prev_values[field] = value
                else:
                    field_null_count[field] += 1

        # Calculate statistics for each field
        total_records = len(data)
        field_stats = {}

        for field in all_fields:
            unique_values = len(field_values[field])
            null_count = field_null_count[field]
            is_unique = unique_values == total_records - field_null_count[field]
            uniqueness_ratio = unique_values / (total_records - field_null_count[field]) if total_records > \
                                                                                            field_null_count[
                                                                                                field] else 0

            # Determine if field is monotonic (either increasing or decreasing)
            is_monotonic = (monotonic_increasing.get(field, False) or
                            monotonic_decreasing.get(field, False))

            field_stats[field] = {
                "unique_values": unique_values,
                "total_records": total_records,
                "null_count": null_count,
                "is_unique": is_unique,
                "uniqueness_ratio": uniqueness_ratio,
                "field_type": field_types.get(field, 'UNKNOWN'),
                "is_monotonic": is_monotonic,
                "monotonic_increasing": monotonic_increasing.get(field, False),
                "monotonic_decreasing": monotonic_decreasing.get(field, False)
            }

        # Calculate a score for each field (considering multiple factors)
        for field, stats in field_stats.items():
            score = 0

            # MODIFICATION 2: Discard fields with NULL values by setting score to 0
            if stats["null_count"] > 0:
                stats["pk_score"] = 0
                stats["disqualified"] = "Contains NULL values"
                continue

            # MODIFICATION 1: Disqualify fields with uniqueness < 99%
            if stats["uniqueness_ratio"] < 0.99:
                stats["pk_score"] = 0
                stats["disqualified"] = "Uniqueness below 99%"
                continue

            # Base score from uniqueness
            score += stats["uniqueness_ratio"] * 50

            # Boost id-like fields
            if field.lower() == 'id' or field.lower().endswith('id') or field.lower().endswith('_id'):
                score += 30

            # Boost monotonic values (good indicator of a designed primary key)
            if stats["is_monotonic"]:
                score += 20

            # Penalize timestamp fields
            if stats["field_type"] in ['TIMESTAMP'] or 'time' in field.lower() or 'date' in field.lower():
                score -= 25

            # Penalize certain field types that are unlikely to be primary keys
            if field.lower() in ['duration', 'port', 'srcport', 'dstport', 'count', 'size', 'length']:
                score -= 30

            stats["pk_score"] = max(0, score)
            stats["disqualified"] = None

        # Sort fields by score (descending)
        sorted_fields = sorted(
            field_stats.items(),
            key=lambda x: (-x[1]["pk_score"], -x[1]["uniqueness_ratio"], x[1]["null_count"])
        )

        # Return the result with best candidate (first non-disqualified field)
        best_candidate = None
        for field, stats in sorted_fields:
            if stats["disqualified"] is None:
                best_candidate = field
                break

        result = {
            "best_candidate": best_candidate,
            "field_stats": dict(sorted_fields)
        }

        return result

    async def analyze_data(self, data_or_json):
        """
        Analyze data and identify the primary key with comprehensive report.

        Args:
            data_or_json: Either a list of dictionaries or a JSON string containing data

        Returns:
            str: Report of the analysis
        """
        try:
            # Parse the data if it's a JSON string
            if isinstance(data_or_json, str):
                data = json.loads(data_or_json)
            else:
                data = data_or_json

            # Identify primary key candidates
            result = await self.identify_primary_key(data)

            if "error" in result:
                return f"Error: {result['error']}"

            # Format the result as a report
            report = []

            # Handle case where no suitable primary key was found
            if result['best_candidate'] is None:
                report.append(f"Analyzed {len(data)} records with {len(result['field_stats'])} fields")
                report.append(
                    f"\nNo suitable primary key candidates found - all fields have NULL values or other disqualifying factors")

                report.append("\nField analysis:")
                for i, (field, stats) in enumerate(result['field_stats'].items()):
                    if i >= 10:  # Show top 10 fields
                        break
                    report.append(f"  {i + 1}. '{field}'")
                    report.append(f"     - Uniqueness: {stats['uniqueness_ratio'] * 100:.2f}%")
                    report.append(f"     - Null values: {stats['null_count']}")
                    report.append(f"     - Data type: {stats['field_type']}")
                    report.append(f"     - Monotonic: {'Yes' if stats.get('is_monotonic', False) else 'No'}")
                    report.append(f"     - PK Score: {stats['pk_score']:.2f}")
                    report.append(f"     - Disqualified: {stats.get('disqualified', 'No')}")

                return "\n".join(report)

            # Normal report with best candidate
            total_records = len(data)
            report.append(f"Analyzed {total_records} records with {len(result['field_stats'])} fields")
            report.append(f"\nBest primary key candidate: '{result['best_candidate']}'")

            best_candidate = result['best_candidate']
            best_stats = result['field_stats'][best_candidate]

            report.append(f"  - Uniqueness: {best_stats['uniqueness_ratio'] * 100:.2f}%")
            report.append(f"  - Unique values: {best_stats['unique_values']} / {total_records}")
            report.append(f"  - Null values: {best_stats['null_count']}")
            report.append(f"  - Data type: {best_stats['field_type']}")
            report.append(
                f"  - Monotonically increasing: {'Yes' if best_stats.get('monotonic_increasing', False) else 'No'}")
            report.append(
                f"  - Monotonically decreasing: {'Yes' if best_stats.get('monotonic_decreasing', False) else 'No'}")
            report.append(f"  - PK Score: {best_stats['pk_score']:.2f}")

            report.append("\nTop candidates (qualifying fields only):")
            count = 0
            for i, (field, stats) in enumerate(result['field_stats'].items()):
                if stats.get('disqualified') is None:
                    count += 1
                    if count > 5:  # Limit to top 5 qualifying fields
                        break
                    report.append(f"  {count}. '{field}'")
                    report.append(f"     - Uniqueness: {stats['uniqueness_ratio'] * 100:.2f}%")
                    report.append(f"     - Unique values: {stats['unique_values']} / {total_records}")
                    report.append(f"     - Null values: {stats['null_count']}")
                    report.append(f"     - Data type: {stats['field_type']}")
                    report.append(
                        f"     - Monotonically increasing: {'Yes' if stats.get('monotonic_increasing', False) else 'No'}")
                    report.append(
                        f"     - Monotonically decreasing: {'Yes' if stats.get('monotonic_decreasing', False) else 'No'}")
                    report.append(f"     - PK Score: {stats['pk_score']:.2f}")

            report.append("\nDisqualified fields:")
            for field, stats in result['field_stats'].items():
                if stats.get('disqualified') is not None:
                    report.append(f"  - '{field}': {stats['disqualified']}")

            return "\n".join(report)

        except Exception as e:
            return f"Error processing data: {str(e)}"

async def main():
    with open('FAZlogs/update.log', 'r') as file:
        log_data = json.load(file)

    analyzer = DataFieldAnalyzer()
    report = await analyzer.analyze_data(json.dumps(log_data))
    print(report)


if __name__ == "__main__":
    asyncio.run(main())