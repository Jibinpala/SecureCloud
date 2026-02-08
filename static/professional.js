// Professional Dashboard JavaScript - Complete Functionality
document.addEventListener('DOMContentLoaded', function () {
    initializeUpload();
    initializeModals();
    initializeFileActions();
    initializeViewControls();
    initializeSearch();
});

// Upload functionality
function initializeUpload() {
    const uploadZone = document.getElementById('uploadZone');
    const fileInput = document.getElementById('fileInput');
    const fileQueue = document.getElementById('fileQueue');
    const uploadBtn = document.getElementById('uploadBtn');

    let selectedFiles = [];

    // Make upload zone clickable
    uploadZone.addEventListener('click', (e) => {
        if (e.target !== fileInput && !e.target.classList.contains('select-btn')) {
            fileInput.click();
        }
    });

    // Drag and drop events
    uploadZone.addEventListener('dragover', (e) => {
        e.preventDefault();
        uploadZone.classList.add('dragover');
    });

    uploadZone.addEventListener('dragleave', (e) => {
        e.preventDefault();
        if (!uploadZone.contains(e.relatedTarget)) {
            uploadZone.classList.remove('dragover');
        }
    });

    uploadZone.addEventListener('drop', (e) => {
        e.preventDefault();
        uploadZone.classList.remove('dragover');
        handleFiles(e.dataTransfer.files);
    });

    // File input change
    fileInput.addEventListener('change', (e) => {
        handleFiles(e.target.files);
    });

    function handleFiles(files) {
        const newFiles = Array.from(files);
        selectedFiles = [...selectedFiles, ...newFiles];

        // Update file input with all files
        const dt = new DataTransfer();
        selectedFiles.forEach(file => dt.items.add(file));
        fileInput.files = dt.files;

        displayFileQueue();
        uploadBtn.style.display = 'block';

        // Ensure button is visible
        setTimeout(() => {
            uploadBtn.scrollIntoView({ behavior: 'smooth', block: 'nearest' });
        }, 100);
    }

    function displayFileQueue() {
        fileQueue.innerHTML = '';
        selectedFiles.forEach((file, index) => {
            const fileItem = document.createElement('div');
            fileItem.className = 'queue-item';
            fileItem.innerHTML = `
                <div class="queue-file-info">
                    <span class="queue-file-name">${file.name}</span>
                    <span class="queue-file-size">${(file.size / 1024).toFixed(1)} KB</span>
                </div>
                <button type="button" onclick="removeQueueFile(${index})" class="queue-remove">×</button>
            `;
            fileQueue.appendChild(fileItem);
        });
    }

    window.removeQueueFile = function (index) {
        selectedFiles.splice(index, 1);
        displayFileQueue();
        uploadBtn.style.display = selectedFiles.length > 0 ? 'block' : 'none';

        // Update file input
        const dt = new DataTransfer();
        selectedFiles.forEach(file => dt.items.add(file));
        fileInput.files = dt.files;
    };

    // Upload form submission
    document.getElementById('uploadForm').addEventListener('submit', function (e) {
        e.preventDefault();
        if (selectedFiles.length > 0) {
            const progressContainer = document.getElementById('uploadProgressContainer');
            const progressFill = document.getElementById('progressFill');
            const progressPercent = document.getElementById('progressPercent');
            const progressStatus = document.getElementById('progressStatus');

            uploadBtn.style.display = 'none';
            progressContainer.style.display = 'block';
            progressStatus.textContent = 'Encrypting & Uploading...';

            const formData = new FormData(this);
            const xhr = new XMLHttpRequest();

            xhr.upload.addEventListener('progress', (e) => {
                if (e.lengthComputable) {
                    const percent = Math.round((e.loaded / e.total) * 100);
                    progressFill.style.width = percent + '%';
                    progressPercent.textContent = percent + '%';
                }
            });

            xhr.onreadystatechange = function () {
                if (xhr.readyState === 4) {
                    try {
                        const data = JSON.parse(xhr.responseText);
                        if (data.status === 'success') {
                            progressStatus.textContent = 'Upload Complete!';
                            showNotification(data.message, 'success');
                            setTimeout(() => location.reload(), 1000);
                        } else {
                            showNotification(data.message || 'Upload failed', 'error');
                            uploadBtn.style.display = 'block';
                            progressContainer.style.display = 'none';
                        }
                    } catch (err) {
                        showNotification('Upload failed. Server error.', 'error');
                        uploadBtn.style.display = 'block';
                        progressContainer.style.display = 'none';
                    }
                }
            };

            xhr.open('POST', '/upload');
            xhr.setRequestHeader('X-Requested-With', 'XMLHttpRequest');
            xhr.send(formData);
        }
    });
}

// Modal functionality
function initializeModals() {
    window.openUploadModal = function () {
        document.getElementById('uploadModal').style.display = 'flex';
    };

    window.openSearchModal = function () {
        document.getElementById('searchModal').style.display = 'flex';
    };

    window.closeModal = function (modalId) {
        document.getElementById(modalId).style.display = 'none';

        // Reset upload form if closing upload modal
        if (modalId === 'uploadModal') {
            document.getElementById('fileQueue').innerHTML = '';
            document.getElementById('uploadBtn').style.display = 'none';
            document.getElementById('fileInput').value = '';
            document.getElementById('uploadBtn').textContent = 'Upload Files';
            document.getElementById('uploadBtn').disabled = false;
        }
    };

    // Close modal when clicking outside
    document.querySelectorAll('.modal').forEach(modal => {
        modal.addEventListener('click', (e) => {
            if (e.target === modal) {
                modal.style.display = 'none';
            }
        });
    });
}

// File actions
function initializeFileActions() {
    window.previewFile = function (fileId) {
        window.location.href = `/preview/${fileId}`;
    };

    window.shareFile = function (fileId) {
        fetch(`/share/${fileId}`)
            .then(response => response.json())
            .then(data => {
                if (data.share_url) {
                    const shareModal = createShareModal(data.share_url, data.expires);
                    document.body.appendChild(shareModal);
                    shareModal.style.display = 'flex';
                }
            })
            .catch(() => showNotification('Failed to generate share link', 'error'));
    };

    window.downloadFile = function (fileId) {
        window.location.href = `/download/${fileId}`;
        showNotification('Download started', 'success');
    };

    window.editFile = function (fileId) {
        // Simple edit functionality - redirect to edit page or show edit modal
        showNotification('Edit functionality - coming soon', 'info');
    };

    window.deleteFile = function (fileId) {
        if (confirm('Delete this file? This action cannot be undone.')) {
            fetch(`/delete/${fileId}`, {
                method: 'DELETE',
                headers: {
                    'X-Requested-With': 'XMLHttpRequest'
                }
            })
                .then(response => response.json())
                .then(data => {
                    if (data.status === 'success') {
                        showNotification('File deleted successfully', 'success');
                        // Find and remove the card from the UI
                        const card = document.querySelector(`[data-file-id="${fileId}"]`);
                        if (card) {
                            card.classList.add('kx-fade-out');
                            setTimeout(() => card.remove(), 500);
                        } else {
                            // Fallback if card lookup fails
                            setTimeout(() => location.reload(), 500);
                        }
                    } else {
                        showNotification(data.message || 'Failed to delete file', 'error');
                    }
                })
                .catch(() => showNotification('Failed to delete file', 'error'));
        }
    };
}

// View controls
function initializeViewControls() {
    const viewBtns = document.querySelectorAll('.view-btn');
    const fileGrid = document.getElementById('fileGrid');

    viewBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            viewBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');

            const view = btn.dataset.view;
            if (view === 'list') {
                fileGrid.classList.add('list-view');
            } else {
                fileGrid.classList.remove('list-view');
            }
        });
    });
}

// Search functionality
function initializeSearch() {
    let searchTimeout;

    window.searchFiles = function () {
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(() => {
            const query = document.getElementById('searchInput').value.toLowerCase();
            const typeFilter = document.getElementById('typeFilter').value;
            const dateFilter = document.getElementById('dateFilter').value;
            const results = document.getElementById('searchResults');

            // Get all file rows for client-side search
            const fileRows = document.querySelectorAll('.file-row');
            const matchedFiles = [];

            fileRows.forEach(row => {
                const fileName = row.querySelector('div').textContent.toLowerCase();
                const fileType = row.dataset.type || '';
                const fileDate = row.dataset.date || '';

                let matches = true;
                if (query && !fileName.includes(query)) matches = false;

                // Show/hide row directly
                row.style.display = matches ? '' : 'none';

            });
        }, 300);
    };

    function displaySearchResults(files) {
        const results = document.getElementById('searchResults');

        if (files.length === 0) {
            results.innerHTML = '<p>No files found</p>';
            return;
        }

        results.innerHTML = files.map(file => `
            <div class="search-result-item">
                <div class="search-file-info">
                    <div class="search-file-name">${file.name}</div>
                    <div class="search-file-meta">${file.size} • ${file.date}</div>
                </div>
                <div class="search-file-actions">
                    <button onclick="downloadFile('${file.id}')" class="search-action-btn">⬇️</button>
                    <button onclick="previewFile('${file.id}')" class="search-action-btn">👁️</button>
                </div>
            </div>
        `).join('');
    }
}

// Sorting functionality
window.sortFiles = function (sortBy) {
    const fileTableBody = document.getElementById('fileTableBody');
    const fileRows = Array.from(fileTableBody.querySelectorAll('.file-row'));

    fileRows.sort((a, b) => {
        switch (sortBy) {
            case 'name':
                return a.querySelector('div').textContent.trim().localeCompare(b.querySelector('div').textContent.trim());
            case 'size':
                // Extraction of size might need refinement if more complex
                return 0; // Simplified for now
            case 'date':
                return 0; // Simplified for now
            default:
                return 0;
        }
    });

    // Re-append sorted rows
    fileRows.forEach(row => fileTableBody.appendChild(row));
    showNotification(`Files sorted by ${sortBy}`, 'info');
};

// Utility functions
function createShareModal(shareUrl, expires) {
    const modal = document.createElement('div');
    modal.className = 'modal';
    modal.innerHTML = `
        <div class="modal-content">
            <div class="modal-header">
                <h3>Share File</h3>
                <span class="close" onclick="this.closest('.modal').remove()">&times;</span>
            </div>
            <div class="modal-body">
                <div class="share-link-container">
                    <label>Secure Link:</label>
                    <input type="text" value="${shareUrl}" readonly class="share-input">
                    <button onclick="copyToClipboard('${shareUrl}')" class="copy-btn">Copy</button>
                </div>
                <p class="share-info">Link expires: ${new Date(expires).toLocaleString()}</p>
            </div>
        </div>
    `;

    modal.addEventListener('click', (e) => {
        if (e.target === modal) {
            modal.remove();
        }
    });

    return modal;
}

function copyToClipboard(text) {
    navigator.clipboard.writeText(text).then(() => {
        showNotification('Link copied to clipboard!', 'success');
    }).catch(() => {
        // Fallback for older browsers
        const textArea = document.createElement('textarea');
        textArea.value = text;
        document.body.appendChild(textArea);
        textArea.select();
        document.execCommand('copy');
        document.body.removeChild(textArea);
        showNotification('Link copied to clipboard!', 'success');
    });
}

function showNotification(message, type = 'info') {
    const notification = document.createElement('div');
    notification.className = `notification ${type}`;
    notification.textContent = message;

    // Create notifications container if it doesn't exist
    let container = document.getElementById('notifications');
    if (!container) {
        container = document.createElement('div');
        container.id = 'notifications';
        container.className = 'notifications';
        document.body.appendChild(container);
    }

    container.appendChild(notification);

    setTimeout(() => notification.classList.add('show'), 100);
    setTimeout(() => {
        notification.classList.remove('show');
        setTimeout(() => notification.remove(), 300);
    }, 3000);
}

// Additional utility functions
window.generateApiKey = function () {
    window.location.href = '/settings';
};

window.toggleTheme = function () {
    document.body.classList.toggle('dark-theme');
    const icon = document.getElementById('theme-icon');
    icon.textContent = document.body.classList.contains('dark-theme') ? '☀️' : '🌙';

    // Save theme preference
    localStorage.setItem('theme', document.body.classList.contains('dark-theme') ? 'dark' : 'light');
};

// Load saved theme on page load
document.addEventListener('DOMContentLoaded', function () {
    const savedTheme = localStorage.getItem('theme');
    if (savedTheme === 'dark') {
        document.body.classList.add('dark-theme');
        document.getElementById('theme-icon').textContent = '☀️';
    }
});