/**
 * KxUI Utility System
 * Unified handling for neon toasts and protocol confirmations.
 */
const KxUI = {
    toast(msg, type = 'success') {
        let container = document.getElementById('kxToastContainer');
        if (!container) {
            container = document.createElement('div');
            container.id = 'kxToastContainer';
            container.className = 'kx-toast-container';
            document.body.appendChild(container);
        }

        const toast = document.createElement('div');
        toast.className = `kx-toast ${type}`;
        toast.innerHTML = `
            <div style="font-size: 1.5rem;">${type === 'success' ? '🛡️' : '⚠️'}</div>
            <div style="flex: 1;">
                <div style="font-size: 0.7rem; text-transform: uppercase; color: var(--primary); font-weight: 800; margin-bottom: 0.2rem;">SYSTEM FEED</div>
                <div style="font-size: 0.9rem;">${msg}</div>
            </div>
        `;
        container.appendChild(toast);
        setTimeout(() => toast.classList.add('active'), 10);
        setTimeout(() => {
            toast.classList.remove('active');
            setTimeout(() => toast.remove(), 400);
        }, 4000);
    },

    success(msg) { this.toast(msg, 'success'); },
    error(msg) { this.toast(msg, 'error'); },

    confirm(msg, onConfirm) {
        let overlay = document.getElementById('kxConfirmOverlay');
        if (!overlay) {
            // Create overlay if not present
            overlay = document.createElement('div');
            overlay.id = 'kxConfirmOverlay';
            overlay.className = 'kx-confirm-overlay';
            overlay.innerHTML = `
                <div class="kx-confirm-card">
                    <div class="kx-confirm-title">Protocol Confirmation</div>
                    <p class="kx-confirm-text" id="kxConfirmText"></p>
                    <div class="kx-confirm-actions">
                        <button class="kx-confirm-btn kx-btn-cancel" onclick="KxUI.closeConfirm()">ABORT</button>
                        <button class="kx-confirm-btn kx-btn-confirm" id="kxConfirmBtn">EXECUTE</button>
                    </div>
                </div>
            `;
            document.body.appendChild(overlay);
        }

        const text = document.getElementById('kxConfirmText');
        const btn = document.getElementById('kxConfirmBtn');

        text.innerText = msg;
        overlay.style.display = 'flex';
        setTimeout(() => overlay.classList.add('active'), 10);

        const handleConfirm = () => {
            overlay.classList.remove('active');
            setTimeout(() => overlay.style.display = 'none', 300);
            btn.removeEventListener('click', handleConfirm);
            if (onConfirm) onConfirm();
        };

        // Clear existing listeners
        const newBtn = btn.cloneNode(true);
        btn.parentNode.replaceChild(newBtn, btn);
        newBtn.addEventListener('click', handleConfirm);
    },

    closeConfirm() {
        const overlay = document.getElementById('kxConfirmOverlay');
        if (overlay) {
            overlay.classList.remove('active');
            setTimeout(() => overlay.style.display = 'none', 300);
        }
    },

    initSidebar() {
        const sidebar = document.querySelector('.sidebar-kx');
        const toggle = document.getElementById('sidebarToggle');

        if (toggle && sidebar) {
            toggle.addEventListener('click', (e) => {
                e.stopPropagation();
                sidebar.classList.toggle('open');
                toggle.classList.toggle('active');
            });

            document.addEventListener('click', (e) => {
                if (window.innerWidth <= 900) {
                    if (!sidebar.contains(e.target) && !toggle.contains(e.target) && sidebar.classList.contains('open')) {
                        sidebar.classList.remove('open');
                        toggle.classList.remove('active');
                    }
                }
            });
        }
    }
};

// Auto-initialize if DOM is ready
document.addEventListener('DOMContentLoaded', () => KxUI.initSidebar());
