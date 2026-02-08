import sqlite3
import threading
import queue
import time
from contextlib import contextmanager
from datetime import datetime
import json

import os
from dotenv import load_dotenv

# Load environment variables
load_dotenv()

class DatabaseManager:
    def __init__(self, db_path=None, pool_size=10):
        self.db_path = db_path or os.getenv("DATABASE_PATH", "database/users.db")
        self.pool_size = pool_size
        self.connection_pool = queue.Queue(maxsize=pool_size)
        self.lock = threading.Lock()
        self._initialize_pool()
        self._create_indexes()

    def _initialize_pool(self):
        """Initialize connection pool"""
        for _ in range(self.pool_size):
            conn = sqlite3.connect(self.db_path, check_same_thread=False)
            conn.row_factory = sqlite3.Row
            conn.execute("PRAGMA foreign_keys = ON")
            conn.execute("PRAGMA journal_mode = WAL")
            conn.execute("PRAGMA synchronous = NORMAL")
            conn.execute("PRAGMA cache_size = 10000")
            conn.execute("PRAGMA temp_store = MEMORY")
            self.connection_pool.put(conn)

    @contextmanager
    def get_connection(self):
        """Get connection from pool"""
        conn = None
        try:
            conn = self.connection_pool.get(timeout=30)
            yield conn
        except queue.Empty:
            raise Exception("Database connection pool exhausted")
        finally:
            if conn:
                self.connection_pool.put(conn)

    def _create_indexes(self):
        """Create database indexes for performance"""
        indexes = [
            "CREATE INDEX IF NOT EXISTS idx_users_username ON users(username)",
            "CREATE INDEX IF NOT EXISTS idx_users_email ON users(email)",
            "CREATE INDEX IF NOT EXISTS idx_documents_username ON documents(username)",
            "CREATE INDEX IF NOT EXISTS idx_documents_type ON documents(document_type)",
            "CREATE INDEX IF NOT EXISTS idx_documents_department ON documents(department)",
            "CREATE INDEX IF NOT EXISTS idx_documents_status ON documents(status)",
            "CREATE INDEX IF NOT EXISTS idx_documents_upload_date ON documents(upload_date)",
            "CREATE INDEX IF NOT EXISTS idx_document_versions_doc_id ON document_versions(document_id)",
            "CREATE INDEX IF NOT EXISTS idx_approval_workflows_doc_id ON approval_workflows(document_id)",
            "CREATE INDEX IF NOT EXISTS idx_approval_workflows_approver ON approval_workflows(approver)",
            "CREATE INDEX IF NOT EXISTS idx_document_access_doc_id ON document_access(document_id)",
            "CREATE INDEX IF NOT EXISTS idx_document_access_username ON document_access(username)",
            "CREATE INDEX IF NOT EXISTS idx_analytics_username ON analytics(username)",
            "CREATE INDEX IF NOT EXISTS idx_analytics_timestamp ON analytics(timestamp)",
            "CREATE INDEX IF NOT EXISTS idx_security_logs_username ON security_logs(username)",
            "CREATE INDEX IF NOT EXISTS idx_security_logs_timestamp ON security_logs(timestamp)"
        ]
        
        with self.get_connection() as conn:
            for index_sql in indexes:
                try:
                    conn.execute(index_sql)
                except sqlite3.Error as e:
                    with open("database/db_error.log", "a") as f:
                        f.write(f"{datetime.now().isoformat()} - Index creation error: {e} - {index_sql}\n")
            conn.commit()

    def execute_query(self, query, params=None, fetch_one=False, fetch_all=False):
        """Execute query with connection pooling"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            try:
                if params:
                    cursor.execute(query, params)
                else:
                    cursor.execute(query)
                
                if fetch_one:
                    return cursor.fetchone()
                elif fetch_all:
                    return cursor.fetchall()
                else:
                    conn.commit()
                    return cursor.lastrowid
            except sqlite3.Error as e:
                conn.rollback()
                raise e

    def execute_many(self, query, params_list):
        """Execute many queries in batch"""
        with self.get_connection() as conn:
            cursor = conn.cursor()
            try:
                cursor.executemany(query, params_list)
                conn.commit()
                return cursor.rowcount
            except sqlite3.Error as e:
                conn.rollback()
                raise e

    def get_user_documents_optimized(self, username, limit=50, offset=0):
        """Optimized query for user documents"""
        query = """
        SELECT d.id, d.original_name, d.document_type, d.department, 
               d.file_size, d.upload_date, d.version, d.status, d.description,
               COUNT(da.id) as access_count
        FROM documents d
        LEFT JOIN document_access da ON d.id = da.document_id
        WHERE d.username = ?
        GROUP BY d.id
        ORDER BY d.upload_date DESC
        LIMIT ? OFFSET ?
        """
        return self.execute_query(query, (username, limit, offset), fetch_all=True)

    def search_documents_full_text(self, username, search_term, filters=None):
        """Full-text search with filters"""
        base_query = """
        SELECT d.id, d.original_name, d.document_type, d.department,
               d.file_size, d.upload_date, d.status, d.description
        FROM documents d
        WHERE (d.username = ? OR d.department IN (
            SELECT department FROM users WHERE username = ?
        )) AND d.status = 'approved'
        """
        
        params = [username, username]
        
        if search_term:
            base_query += " AND (d.original_name LIKE ? OR d.description LIKE ?)"
            search_pattern = f"%{search_term}%"
            params.extend([search_pattern, search_pattern])
        
        if filters:
            if filters.get('document_type'):
                base_query += " AND d.document_type = ?"
                params.append(filters['document_type'])
            
            if filters.get('department'):
                base_query += " AND d.department = ?"
                params.append(filters['department'])
            
            if filters.get('date_from'):
                base_query += " AND d.upload_date >= ?"
                params.append(filters['date_from'])
            
            if filters.get('date_to'):
                base_query += " AND d.upload_date <= ?"
                params.append(filters['date_to'])
        
        base_query += " ORDER BY d.upload_date DESC LIMIT 100"
        
        return self.execute_query(base_query, params, fetch_all=True)

    def get_analytics_dashboard(self, username, days=30):
        """Get analytics data for dashboard"""
        query = """
        SELECT 
            DATE(timestamp) as date,
            action,
            COUNT(*) as count
        FROM analytics 
        WHERE username = ? AND timestamp >= datetime('now', '-{} days')
        GROUP BY DATE(timestamp), action
        ORDER BY date DESC
        """.format(days)
        
        return self.execute_query(query, (username,), fetch_all=True)

    def cleanup_old_data(self, days=90):
        """Cleanup old analytics and access logs"""
        cleanup_queries = [
            ("DELETE FROM analytics WHERE timestamp < datetime('now', '-{} days')".format(days), []),
            ("DELETE FROM document_access WHERE timestamp < datetime('now', '-{} days')".format(days), []),
            ("DELETE FROM security_events WHERE timestamp < datetime('now', '-{} days')".format(days), [])
        ]
        
        for query, params in cleanup_queries:
            try:
                self.execute_query(query, params)
            except sqlite3.Error as e:
                print(f"Cleanup error: {e}")

    def backup_database(self, backup_path):
        """Create database backup"""
        with self.get_connection() as conn:
            with open(backup_path, 'w') as f:
                for line in conn.iterdump():
                    f.write('%s\n' % line)

    def get_database_stats(self):
        """Get database statistics"""
        stats_queries = [
            ("SELECT COUNT(*) as user_count FROM users", "users"),
            ("SELECT COUNT(*) as document_count FROM documents", "documents"),
            ("SELECT COUNT(*) as version_count FROM document_versions", "versions"),
            ("SELECT SUM(file_size) as total_storage FROM documents", "storage"),
            ("SELECT COUNT(*) as pending_approvals FROM approval_workflows WHERE status='pending'", "pending_approvals")
        ]
        
        stats = {}
        for query, key in stats_queries:
            result = self.execute_query(query, fetch_one=True)
            stats[key] = result[0] if result else 0
        
        return stats

# Global database manager instance
db_manager = DatabaseManager()