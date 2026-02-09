import sqlite3
import threading
import queue
import time
from contextlib import contextmanager
from datetime import datetime
import json
import os
from dotenv import load_dotenv

try:
    import psycopg2
    from psycopg2 import pool
    POSTGRES_AVAILABLE = True
except ImportError:
    POSTGRES_AVAILABLE = False

from config import DATABASE_PATH, DATABASE_URL

# Load environment variables
load_dotenv()

class DatabaseManager:
    def __init__(self, db_url=None, db_path=None, pool_size=10):
        self.db_url = db_url or DATABASE_URL
        self.db_path = db_path or DATABASE_PATH
        self.pool_size = pool_size
        self.connection_pool = None
        self.is_postgres = False
        
        self._initialize_pool()
        self._create_indexes()

    def _initialize_pool(self):
        """Initialize connection pool for either Postgres or SQLite"""
        if self.db_url and POSTGRES_AVAILABLE:
            try:
                self.connection_pool = psycopg2.pool.SimpleConnectionPool(
                    1, self.pool_size, self.db_url
                )
                self.is_postgres = True
                print("Connected to PostgreSQL pool")
            except Exception as e:
                print(f"Failed to connect to Postgres: {e}. Falling back to SQLite.")
                self._init_sqlite_pool()
        else:
            self._init_sqlite_pool()

    def _init_sqlite_pool(self):
        """Initialize SQLite connection pool"""
        self.connection_pool = queue.Queue(maxsize=self.pool_size)
        self.is_postgres = False
        for _ in range(self.pool_size):
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")
            self.connection_pool.put(conn)
        print(f"Connected to SQLite: {self.db_path}")

    @contextmanager
    def get_connection(self):
        """Get connection from pool"""
        if self.is_postgres:
            from psycopg2.extras import RealDictCursor
            conn = self.connection_pool.getconn()
            try:
                # Provide a cursor that returns dict-like objects
                yield conn, conn.cursor(cursor_factory=RealDictCursor)
            finally:
                self.connection_pool.putconn(conn)
        else:
            conn = None
            try:
                conn = self.connection_pool.get(timeout=30)
                yield conn, conn.cursor()
            except queue.Empty:
                raise Exception("Database connection pool exhausted")
            finally:
                if conn:
                    self.connection_pool.put(conn)

    def _create_indexes(self):
        """Create database indexes for performance"""
        # Postgres and SQLite syntax for CREATE INDEX IF NOT EXISTS is largely compatible
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)",
            "CREATE INDEX IF NOT EXISTS idx_documents_username ON documents(username)",
            "CREATE INDEX IF NOT EXISTS idx_security_logs_username ON security_logs(username)"
        ]
        
        with self.get_connection() as (conn, cursor):
            for index_sql in indexes:
                try:
                    cursor.execute(index_sql)
                except Exception as e:
                    pass # Table might not exist yet
            conn.commit()

    def execute_query(self, query, params=None, fetch_one=False, fetch_all=False):
        """Execute query with connection pooling"""
        # Convert SQLite '?' placeholder to Postgres '%s' if needed
        if self.is_postgres and params:
            query = query.replace('?', '%s')
            
        with self.get_connection() as (conn, cursor):
            try:
                if params:
                    cursor.execute(query, params)
                else:
                    cursor.execute(query)
                
                if fetch_one:
                    row = cursor.fetchone()
                    return dict(row) if row else None
                elif fetch_all:
                    rows = cursor.fetchall()
                    return [dict(row) for row in rows] if rows else []
                else:
                    conn.commit()
                    return cursor.lastrowid if not self.is_postgres else None
            except Exception as e:
                conn.rollback()
                raise e

# Global database manager instance
db_manager = DatabaseManager()