import datetime
import json
import logging
import os
import pytz
import shutil
import sqlite3
import struct
from pyforensics import __version__
from pathlib import Path

log = logging.getLogger(__name__)


def dict_factory(cursor, row):
    d = {}
    for idx, col in enumerate(cursor.description):
        d[col[0]] = row[idx]
    return d


def open_sqlite_db(chrome, database_path, database_name):
    log.info(f' - Reading from {database_name} in {database_path}')

    if chrome.no_copy:
        db_path_to_open = os.path.join(database_path, database_name)

    else:
        try:
            
            Path(chrome.temp_dir).mkdir(parents=True, exist_ok=True)

            
            db_path_to_open = os.path.join(chrome.temp_dir, database_name)
            shutil.copyfile(os.path.join(database_path, database_name), db_path_to_open)
        except Exception as e:
            log.error(f' - Error copying {database_name}: {e}')
            return None

    try:
        
        db_conn = sqlite3.connect(db_path_to_open)

        
        db_conn.row_factory = dict_factory
    except Exception as e:
        log.error(f' - Error opening {database_name}: {e}')
        return None

    return db_conn


def format_plugin_output(name, version, items):
    width = 80
    left_side = width * 0.55
    full_plugin_name = "{} (v{})".format(name, version)
    pretty_name = "{name:>{left_width}}:{count:^{right_width}}" \
        .format(name=full_plugin_name, left_width=int(left_side), version=version, count=' '.join(['-', items, '-']),
                right_width=(width - int(left_side) - 2))
    return pretty_name


def format_meta_output(name, content):
    left_side = 17
    pretty_name = "{name:>{left_width}}: {content}" \
        .format(name=name, left_width=int(left_side), content=content)
    return pretty_name


class MyEncoder(json.JSONEncoder):
    def default(self, obj):
        if isinstance(obj, datetime.datetime):
            return obj.isoformat()
        elif isinstance(obj, bytes):
            return str(obj, encoding='utf-8', errors='replace')
        else:
            return obj.__dict__


def to_datetime(timestamp, timezone=None):
    """Convert a variety of timestamp formats to a datetime object."""

    try:
        if isinstance(timestamp, datetime.datetime):
            return timestamp
        try:
            timestamp = float(timestamp)
        except Exception as e:
            log.warning(f'Exception parsing {timestamp} to datetime: {e}')
            return datetime.datetime.fromtimestamp(0)

        
        
        if timestamp > 13700000000000000:
            new_timestamp = datetime.datetime.fromtimestamp(0) \
                            + datetime.timedelta(seconds=(timestamp / 1000000) - 11644473600)

        
        elif timestamp > 12000000000000000:  
            new_timestamp = datetime.datetime.utcfromtimestamp((timestamp / 1000000) - 11644473600)

        
        elif 2500000000000 > timestamp > 1280000000000:  
            new_timestamp = datetime.datetime.utcfromtimestamp(timestamp / 1000)

        
        elif 15000000000 > timestamp >= 12900000000:  
            new_timestamp = datetime.datetime.utcfromtimestamp(timestamp - 11644473600)

        
        else:
            new_timestamp = datetime.datetime.utcfromtimestamp(timestamp)

        if timezone is not None:
            try:
                return new_timestamp.replace(tzinfo=pytz.utc).astimezone(timezone)
            except NameError:
                return new_timestamp
        else:
            return new_timestamp
    except Exception as e:
        log.warning(f'Exception parsing {timestamp} to datetime: {e}')
        return datetime.datetime.fromtimestamp(0)


def friendly_date(timestamp):
    if isinstance(timestamp, (str, int)):
        return to_datetime(timestamp).strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
    elif timestamp is None:
        return ''
    else:
        return timestamp.strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]


def get_ldb_records(ldb_path, prefix=''):
    """Open a LevelDB at given path and return a list of records, optionally
    filtered by a prefix string. Key and value are kept as byte strings."""

    try:
        from pyforensics.lib.ccl_chrome_indexeddb import ccl_leveldb
    except ImportError:
        log.warning(f' - Failed to import ccl_leveldb; unable to process {ldb_path}')
        return []

    
    
    if isinstance(prefix, str):
        prefix = prefix.encode()

    try:
        db = ccl_leveldb.RawLevelDb(ldb_path)
    except Exception as e:
        log.warning(f' - Could not open {ldb_path} as LevelDB; {e}')
        return []

    cleaned_records = []

    try:
        for record in db.iterate_records_raw():
            cleaned_record = record.__dict__

            if record.file_type.name == 'Ldb':
                cleaned_record['key'] = record.key[:-8]

            if cleaned_record['key'].startswith(prefix):
                cleaned_record['key'] = cleaned_record['key'][len(prefix):]
                cleaned_record['state'] = cleaned_record['state'].name
                cleaned_record['file_type'] = cleaned_record['file_type'].name

                cleaned_records.append(cleaned_record)

    except ValueError:
        log.warning(f' - Exception reading LevelDB: ValueError')

    except Exception as e:
        log.warning(f' - Exception reading LevelDB: {e}')

    db.close()
    return cleaned_records


def read_varint(source):
    result = 0
    bytes_used = 0
    for read in source:
        result |= ((read & 0x7F) << (bytes_used * 7))
        bytes_used += 1
        if (read & 0x80) != 0x80:
            return result, bytes_used


def read_string(input_bytes, ptr):
    length = struct.unpack('<i', input_bytes[ptr:ptr+4])[0]
    ptr += 4
    end_ptr = ptr+length
    string_value = input_bytes[ptr:end_ptr]
    while end_ptr % 4 != 0:
        end_ptr += 1

    return string_value.decode(), end_ptr


def read_int32(input_bytes, ptr):
    value = struct.unpack('<i', input_bytes[ptr:ptr + 4])[0]
    return value, ptr + 4


def read_int64(input_bytes, ptr):
    value = struct.unpack('<Q', input_bytes[ptr:ptr + 8])[0]
    return value, ptr + 8















banner = r''''''
