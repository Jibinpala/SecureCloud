import os
import shutil
import json
import zipfile
import time
import threading
from datetime import datetime, timedelta
from pathlib import Path
import hashlib
import sqlite3

class BackupManager:
    def __init__(self, backup_dir="backups"):
        self.backup_dir = Path(backup_dir)
        self.backup_dir.mkdir(exist_ok=True)
        self.retention_days = 30
        self.setup_scheduled_backups()

    def create_full_backup(self):
        """Create full system backup"""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        backup_name = f"securecloud_backup_{timestamp}"
        backup_path = self.backup_dir / f"{backup_name}.zip"
        
        try:
            with zipfile.ZipFile(backup_path, 'w', zipfile.ZIP_DEFLATED) as zipf:
                # Backup database
                if os.path.exists("database/users.db"):
                    zipf.write("database/users.db", "database/users.db")
                
                # Backup encrypted files
                if os.path.exists("encrypted_files"):
                    for root, dirs, files in os.walk("encrypted_files"):
                        for file in files:
                            file_path = os.path.join(root, file)
                            arcname = os.path.relpath(file_path, ".")
                            zipf.write(file_path, arcname)
                
                # Backup configuration files
                config_files = ["config.py", "secret.key", "requirements.txt"]
                for config_file in config_files:
                    if os.path.exists(config_file):
                        zipf.write(config_file, config_file)
                
                # Create backup manifest
                manifest = {
                    "backup_date": datetime.now().isoformat(),
                    "backup_type": "full",
                    "version": "1.0",
                    "files_count": len(zipf.namelist())
                }
                
                zipf.writestr("backup_manifest.json", json.dumps(manifest, indent=2))
            
            # Verify backup integrity
            if self.verify_backup(backup_path):
                self.log_backup_event("SUCCESS", f"Full backup created: {backup_name}")
                return str(backup_path)
            else:
                os.remove(backup_path)
                self.log_backup_event("ERROR", f"Backup verification failed: {backup_name}")
                return None
                
        except Exception as e:
            self.log_backup_event("ERROR", f"Backup creation failed: {str(e)}")
            return None

    def verify_backup(self, backup_path):
        """Verify backup integrity"""
        try:
            with zipfile.ZipFile(backup_path, 'r') as zipf:
                # Test zip file integrity
                bad_file = zipf.testzip()
                if bad_file:
                    return False
                
                # Check if manifest exists
                if "backup_manifest.json" not in zipf.namelist():
                    return False
                
                # Verify essential files
                essential_files = ["database/users.db"]
                for file in essential_files:
                    if file not in zipf.namelist():
                        return False
                
                return True
        except Exception:
            return False

    def restore_backup(self, backup_path, restore_dir="restore"):
        """Restore from backup"""
        restore_path = Path(restore_dir)
        restore_path.mkdir(exist_ok=True)
        
        try:
            with zipfile.ZipFile(backup_path, 'r') as zipf:
                zipf.extractall(restore_path)
            
            self.log_backup_event("SUCCESS", f"Backup restored to: {restore_path}")
            return str(restore_path)
            
        except Exception as e:
            self.log_backup_event("ERROR", f"Restore failed: {str(e)}")
            return None

    def cleanup_old_backups(self):
        """Remove old backups based on retention policy"""
        cutoff_date = datetime.now() - timedelta(days=self.retention_days)
        
        for backup_file in self.backup_dir.glob("securecloud_backup_*.zip"):
            if backup_file.stat().st_mtime < cutoff_date.timestamp():
                try:
                    backup_file.unlink()
                    self.log_backup_event("INFO", f"Deleted old backup: {backup_file.name}")
                except Exception as e:
                    self.log_backup_event("ERROR", f"Failed to delete backup: {str(e)}")

    def setup_scheduled_backups(self):
        """Setup automatic backup scheduling (simplified)"""
        def run_scheduler():
            while True:
                # Simple daily backup at 2 AM
                now = datetime.now()
                if now.hour == 2 and now.minute == 0:
                    self.create_full_backup()
                    time.sleep(60)  # Wait a minute to avoid duplicate runs
                
                # Weekly cleanup
                if now.weekday() == 0 and now.hour == 3:  # Monday at 3 AM
                    self.cleanup_old_backups()
                    time.sleep(3600)  # Wait an hour
                
                time.sleep(60)  # Check every minute
        
        scheduler_thread = threading.Thread(target=run_scheduler, daemon=True)
        scheduler_thread.start()

    def log_backup_event(self, level, message):
        """Log backup events"""
        log_entry = {
            "timestamp": datetime.now().isoformat(),
            "level": level,
            "message": message
        }
        
        log_file = self.backup_dir / "backup.log"
        with open(log_file, "a") as f:
            f.write(json.dumps(log_entry) + "\n")

class ComplianceManager:
    def __init__(self):
        self.compliance_dir = Path("compliance")
        self.compliance_dir.mkdir(exist_ok=True)

    def generate_audit_report(self, start_date, end_date, username=None):
        """Generate compliance audit report"""
        conn = sqlite3.connect("database/users.db")
        c = conn.cursor()
        
        # Base query for audit events
        base_query = """
        SELECT timestamp, username, action, resource, ip_address, metadata
        FROM analytics
        WHERE timestamp BETWEEN ? AND ?
        """
        
        params = [start_date, end_date]
        
        if username:
            base_query += " AND username = ?"
            params.append(username)
        
        base_query += " ORDER BY timestamp DESC"
        
        c.execute(base_query, params)
        audit_events = c.fetchall()
        
        # Generate report
        report = {
            "report_id": hashlib.md5(f"{start_date}{end_date}{username}".encode()).hexdigest()[:8],
            "generated_at": datetime.now().isoformat(),
            "period": {"start": start_date, "end": end_date},
            "scope": {"username": username} if username else {"scope": "all_users"},
            "total_events": len(audit_events),
            "events": []
        }
        
        for event in audit_events:
            report["events"].append({
                "timestamp": event[0],
                "user": event[1],
                "action": event[2],
                "resource": event[3],
                "ip_address": event[4],
                "metadata": json.loads(event[5]) if event[5] else None
            })
        
        # Save report
        report_file = self.compliance_dir / f"audit_report_{report['report_id']}.json"
        with open(report_file, "w") as f:
            json.dump(report, f, indent=2)
        
        conn.close()
        return report

    def generate_gdpr_report(self, username):
        """Generate GDPR data export for user"""
        conn = sqlite3.connect("database/users.db")
        c = conn.cursor()
        
        # User data
        c.execute("SELECT * FROM users WHERE username = ?", (username,))
        user_data = dict(c.fetchone()) if c.fetchone() else {}
        
        # User documents
        c.execute("SELECT * FROM documents WHERE username = ?", (username,))
        documents = [dict(row) for row in c.fetchall()]
        
        # User analytics
        c.execute("SELECT * FROM analytics WHERE username = ?", (username,))
        analytics = [dict(row) for row in c.fetchall()]
        
        # User access logs
        c.execute("SELECT * FROM document_access WHERE username = ?", (username,))
        access_logs = [dict(row) for row in c.fetchall()]
        
        gdpr_export = {
            "export_date": datetime.now().isoformat(),
            "username": username,
            "user_profile": user_data,
            "documents": documents,
            "activity_logs": analytics,
            "access_logs": access_logs
        }
        
        # Save GDPR export
        export_file = self.compliance_dir / f"gdpr_export_{username}_{datetime.now().strftime('%Y%m%d')}.json"
        with open(export_file, "w") as f:
            json.dump(gdpr_export, f, indent=2)
        
        conn.close()
        return str(export_file)

    def delete_user_data(self, username, confirmation_code):
        """GDPR compliant user data deletion"""
        expected_code = hashlib.sha256(f"DELETE_{username}_{datetime.now().strftime('%Y%m%d')}".encode()).hexdigest()[:8]
        
        if confirmation_code != expected_code:
            raise ValueError("Invalid confirmation code")
        
        conn = sqlite3.connect("database/users.db")
        c = conn.cursor()
        
        try:
            # Delete user files
            user_folder = Path("encrypted_files") / "users" / username
            if user_folder.exists():
                shutil.rmtree(user_folder)
            
            # Delete database records
            tables_to_clean = [
                "document_access", "analytics", "approval_workflows",
                "document_versions", "documents", "users"
            ]
            
            for table in tables_to_clean:
                c.execute(f"DELETE FROM {table} WHERE username = ?", (username,))
            
            conn.commit()
            
            # Log deletion
            deletion_log = {
                "timestamp": datetime.now().isoformat(),
                "username": username,
                "action": "GDPR_DATA_DELETION",
                "confirmation_code": confirmation_code
            }
            
            log_file = self.compliance_dir / "data_deletions.log"
            with open(log_file, "a") as f:
                f.write(json.dumps(deletion_log) + "\n")
            
            return True
            
        except Exception as e:
            conn.rollback()
            raise e
        finally:
            conn.close()

    def generate_retention_report(self):
        """Generate data retention compliance report"""
        conn = sqlite3.connect("database/users.db")
        c = conn.cursor()
        
        # Check for old data that should be archived/deleted
        retention_periods = {
            "analytics": 365,  # 1 year
            "document_access": 180,  # 6 months
            "security_events": 90   # 3 months
        }
        
        report = {
            "generated_at": datetime.now().isoformat(),
            "retention_analysis": {}
        }
        
        for table, days in retention_periods.items():
            cutoff_date = (datetime.now() - timedelta(days=days)).isoformat()
            
            c.execute(f"SELECT COUNT(*) FROM {table} WHERE timestamp < ?", (cutoff_date,))
            old_records = c.fetchone()[0]
            
            report["retention_analysis"][table] = {
                "retention_period_days": days,
                "cutoff_date": cutoff_date,
                "records_to_archive": old_records
            }
        
        conn.close()
        return report

# Global instances
backup_manager = BackupManager()
compliance_manager = ComplianceManager()