import asyncio
import hashlib
import json
import time
from functools import wraps
from threading import Thread
import queue
import os
from datetime import datetime, timedelta

class CacheManager:
    def __init__(self, max_size=1000, ttl=3600):
        self.cache = {}
        self.access_times = {}
        self.max_size = max_size
        self.ttl = ttl  # Time to live in seconds

    def get(self, key):
        """Get item from cache"""
        if key in self.cache:
            # Check if expired
            if time.time() - self.access_times[key] > self.ttl:
                del self.cache[key]
                del self.access_times[key]
                return None
            
            self.access_times[key] = time.time()
            return self.cache[key]
        return None

    def set(self, key, value):
        """Set item in cache"""
        # Clean expired items
        self._cleanup_expired()
        
        # Remove oldest items if cache is full
        if len(self.cache) >= self.max_size:
            oldest_key = min(self.access_times.keys(), key=lambda k: self.access_times[k])
            del self.cache[oldest_key]
            del self.access_times[oldest_key]
        
        self.cache[key] = value
        self.access_times[key] = time.time()

    def delete(self, key):
        """Delete item from cache"""
        if key in self.cache:
            del self.cache[key]
            del self.access_times[key]

    def _cleanup_expired(self):
        """Remove expired items"""
        current_time = time.time()
        expired_keys = [
            key for key, access_time in self.access_times.items()
            if current_time - access_time > self.ttl
        ]
        
        for key in expired_keys:
            del self.cache[key]
            del self.access_times[key]

def cache_result(ttl=3600):
    """Decorator for caching function results"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            # Create cache key from function name and arguments
            cache_key = f"{func.__name__}:{hashlib.md5(str(args + tuple(kwargs.items())).encode()).hexdigest()}"
            
            # Try to get from cache
            cached_result = cache_manager.get(cache_key)
            if cached_result is not None:
                return cached_result
            
            # Execute function and cache result
            result = func(*args, **kwargs)
            cache_manager.set(cache_key, result)
            return result
        return wrapper
    return decorator

class FileChunkManager:
    def __init__(self, chunk_size=1024*1024):  # 1MB chunks
        self.chunk_size = chunk_size

    def upload_chunked_file(self, file_path, file_data, progress_callback=None):
        """Upload file in chunks with progress tracking"""
        total_size = len(file_data)
        chunks_uploaded = 0
        total_chunks = (total_size + self.chunk_size - 1) // self.chunk_size
        
        with open(file_path, 'wb') as f:
            for i in range(0, total_size, self.chunk_size):
                chunk = file_data[i:i + self.chunk_size]
                f.write(chunk)
                chunks_uploaded += 1
                
                if progress_callback:
                    progress = (chunks_uploaded / total_chunks) * 100
                    progress_callback(progress)
        
        return True

    def download_chunked_file(self, file_path, progress_callback=None):
        """Download file in chunks with progress tracking"""
        if not os.path.exists(file_path):
            return None
        
        file_size = os.path.getsize(file_path)
        chunks_read = 0
        total_chunks = (file_size + self.chunk_size - 1) // self.chunk_size
        
        file_data = b''
        
        with open(file_path, 'rb') as f:
            while True:
                chunk = f.read(self.chunk_size)
                if not chunk:
                    break
                
                file_data += chunk
                chunks_read += 1
                
                if progress_callback:
                    progress = (chunks_read / total_chunks) * 100
                    progress_callback(progress)
        
        return file_data

class AsyncTaskManager:
    def __init__(self, max_workers=5):
        self.task_queue = queue.Queue()
        self.result_store = {}
        self.max_workers = max_workers
        self.workers = []
        self._start_workers()

    def _start_workers(self):
        """Start background worker threads"""
        for i in range(self.max_workers):
            worker = Thread(target=self._worker, daemon=True)
            worker.start()
            self.workers.append(worker)

    def _worker(self):
        """Background worker thread"""
        while True:
            try:
                task_id, func, args, kwargs = self.task_queue.get(timeout=1)
                
                try:
                    result = func(*args, **kwargs)
                    self.result_store[task_id] = {
                        'status': 'completed',
                        'result': result,
                        'completed_at': datetime.now().isoformat()
                    }
                except Exception as e:
                    self.result_store[task_id] = {
                        'status': 'failed',
                        'error': str(e),
                        'completed_at': datetime.now().isoformat()
                    }
                
                self.task_queue.task_done()
                
            except queue.Empty:
                continue

    def submit_task(self, func, *args, **kwargs):
        """Submit task for background processing"""
        task_id = hashlib.md5(f"{func.__name__}{time.time()}".encode()).hexdigest()[:8]
        
        self.result_store[task_id] = {
            'status': 'pending',
            'submitted_at': datetime.now().isoformat()
        }
        
        self.task_queue.put((task_id, func, args, kwargs))
        return task_id

    def get_task_status(self, task_id):
        """Get task status and result"""
        return self.result_store.get(task_id, {'status': 'not_found'})

    def cleanup_completed_tasks(self, max_age_hours=24):
        """Clean up old completed tasks"""
        cutoff_time = datetime.now() - timedelta(hours=max_age_hours)
        
        tasks_to_remove = []
        for task_id, task_info in self.result_store.items():
            if 'completed_at' in task_info:
                completed_time = datetime.fromisoformat(task_info['completed_at'])
                if completed_time < cutoff_time:
                    tasks_to_remove.append(task_id)
        
        for task_id in tasks_to_remove:
            del self.result_store[task_id]

class PerformanceMonitor:
    def __init__(self):
        self.metrics = {}
        self.start_time = time.time()

    def record_metric(self, name, value, timestamp=None):
        """Record a performance metric"""
        if timestamp is None:
            timestamp = time.time()
        
        if name not in self.metrics:
            self.metrics[name] = []
        
        self.metrics[name].append({
            'value': value,
            'timestamp': timestamp
        })
        
        # Keep only last 1000 entries per metric
        if len(self.metrics[name]) > 1000:
            self.metrics[name] = self.metrics[name][-1000:]

    def get_average(self, name, window_seconds=3600):
        """Get average value for a metric within time window"""
        if name not in self.metrics:
            return None
        
        cutoff_time = time.time() - window_seconds
        recent_values = [
            entry['value'] for entry in self.metrics[name]
            if entry['timestamp'] > cutoff_time
        ]
        
        if not recent_values:
            return None
        
        return sum(recent_values) / len(recent_values)

    def get_system_stats(self):
        """Get system performance statistics"""
        try:
            import psutil
            return {
                'cpu_percent': psutil.cpu_percent(),
                'memory_percent': psutil.virtual_memory().percent,
                'disk_usage': psutil.disk_usage('/').percent,
                'uptime_seconds': time.time() - self.start_time
            }
        except ImportError:
            return {
                'cpu_percent': 0,
                'memory_percent': 0,
                'disk_usage': 0,
                'uptime_seconds': time.time() - self.start_time
            }

def monitor_performance(metric_name):
    """Decorator to monitor function performance"""
    def decorator(func):
        @wraps(func)
        def wrapper(*args, **kwargs):
            start_time = time.time()
            
            try:
                result = func(*args, **kwargs)
                execution_time = time.time() - start_time
                performance_monitor.record_metric(f"{metric_name}_success", execution_time)
                return result
            except Exception as e:
                execution_time = time.time() - start_time
                performance_monitor.record_metric(f"{metric_name}_error", execution_time)
                raise e
        return wrapper
    return decorator

class SearchOptimizer:
    def __init__(self):
        self.search_index = {}
        self.last_index_update = 0
        self.index_ttl = 3600  # 1 hour

    def build_search_index(self, documents):
        """Build search index for documents"""
        index = {}
        
        for doc in documents:
            doc_id = doc['id']
            searchable_text = f"{doc['original_name']} {doc.get('description', '')}".lower()
            
            # Simple word-based indexing
            words = searchable_text.split()
            for word in words:
                if len(word) > 2:  # Skip very short words
                    if word not in index:
                        index[word] = set()
                    index[word].add(doc_id)
        
        self.search_index = index
        self.last_index_update = time.time()

    def search_documents(self, query, documents):
        """Optimized document search"""
        # Rebuild index if stale
        if time.time() - self.last_index_update > self.index_ttl:
            self.build_search_index(documents)
        
        if not query:
            return documents
        
        query_words = query.lower().split()
        matching_doc_ids = None
        
        for word in query_words:
            word_matches = self.search_index.get(word, set())
            
            if matching_doc_ids is None:
                matching_doc_ids = word_matches
            else:
                matching_doc_ids = matching_doc_ids.intersection(word_matches)
        
        if matching_doc_ids is None:
            return []
        
        # Return matching documents
        return [doc for doc in documents if doc['id'] in matching_doc_ids]

# Global instances
cache_manager = CacheManager()
file_chunk_manager = FileChunkManager()
async_task_manager = AsyncTaskManager()
performance_monitor = PerformanceMonitor()
search_optimizer = SearchOptimizer()