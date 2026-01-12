"""
FORTRESS VAULT - Professional GUI Password Manager
=================================================
Features:
- Modern dark theme interface
- Secure password visibility toggle
- Auto-fill with clipboard support
- Search and filter passwords
- Complete anti-forensic cleanup
- Hardware-bound encryption
"""

import os, sys, json, time, hashlib, hmac, sqlite3, subprocess, secrets, gc, atexit
from datetime import datetime, timedelta
import threading
import ctypes
from ctypes import c_char_p, c_size_t, POINTER, c_void_p

try:
    import customtkinter as ctk
    import pyotp
    import qrcode
    from PIL import Image, ImageTk
    import pyautogui
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    from argon2.low_level import hash_secret_raw, Type
except ImportError as e:
    print(f"❌ Missing dependency: {e}")
    print("Install: pip install customtkinter pyotp qrcode pillow pyautogui cryptography argon2-cffi pyperclip")
    sys.exit(1)


import string
import secrets
import subprocess
import hashlib
import ctypes
import sys
from argon2.low_level import hash_secret_raw, Type


def resource_path(relative_path):
    """ Get absolute path to resource, works for dev and for PyInstaller """
    try:
        # PyInstaller creates a temp folder and stores path in _MEIPASS
        base_path = sys._MEIPASS
    except Exception:
        base_path = os.path.abspath(".")
    return os.path.join(base_path, relative_path)

def secure_delete_file(path, passes=3):
    """Overwrites a file with random data before physical deletion."""
    if os.path.exists(path):
        try:
            length = os.path.getsize(path)
            # Use 'br+' for binary read/update mode
            with open(path, "br+", buffering=0) as f:
                for _ in range(passes):
                    f.seek(0)
                    f.write(secrets.token_bytes(length))
                    f.flush()
                    os.fsync(f.fileno()) # Bypasses OS write cache
            os.remove(path)
            print(f"🛡️ File securely erased: {path}")
        except Exception as e:
            print(f"⚠️ Secure delete failed for {path}: {e}")
            if os.path.exists(path): os.remove(path)
# Create new ValidationHelper class
class ValidationHelper:
    @staticmethod
    def validate_password_strength(password: str) -> tuple[bool, str]:
        """Returns (is_valid, error_message)"""
        if len(password) < 12:
            return False, "Password must be 12+ characters"
        if not any(c.isupper() for c in password):
            return False, "Must include an UPPERCASE letter"
        if not any(c.islower() for c in password):
            return False, "Must include a lowercase letter"
        if not any(c.isdigit() for c in password):
            return False, "Must include a Number (0-9)"
        if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            return False, "Must include a Symbol (!@#$)"
        return True, ""
    
    @staticmethod
    def validate_entry_fields(site: str, password: str) -> tuple[bool, str]:
        """Validate new password entry"""
        if not site or not site.strip():
            return False, "Site name cannot be empty"
        if not password:
            return False, "Password cannot be empty"
        if len(password) < 8:
            return False, "Password too short (min 8 characters)"
        return True, ""


class DatabaseHelper:
    @staticmethod
    def safe_execute(query: str, params: tuple = (), commit: bool = False):
        """Safely execute database queries with error handling"""
        try:
            with sqlite3.connect("vault.db", timeout=10) as conn:
                cursor = conn.cursor()
                cursor.execute(query, params)
                if commit:
                    conn.commit()
                return cursor.fetchall()
        except sqlite3.IntegrityError as e:
            raise ValueError(f"Data integrity error: {e}")
        except sqlite3.OperationalError as e:
            raise RuntimeError(f"Database locked or inaccessible: {e}")
        except Exception as e:
            raise RuntimeError(f"Database error: {e}")


# --- ENHANCED SECURITY CORE ---
class SecurityCore:
    @staticmethod
    def encrypt_secret(master_key: bytes, plaintext: str) -> tuple[bytes, bytes]:
        """Encrypts data with native AES-256-GCM authentication."""
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(master_key)
        # encrypt returns ciphertext + 16-byte tag appended automatically
        ciphertext_with_tag = aesgcm.encrypt(nonce, plaintext.encode('utf-8'), None)
        return nonce, ciphertext_with_tag

    @staticmethod
    def decrypt_secret(master_key: bytes, nonce: bytes, ciphertext: bytes) -> bytearray:
        """Decrypts and returns a mutable bytearray for secure wiping."""
        aesgcm = AESGCM(master_key)
        # decrypt automatically validates the tag; raises InvalidTag if tampered
        decrypted_bytes = aesgcm.decrypt(nonce, ciphertext, None)
        return bytearray(decrypted_bytes)


    @staticmethod
    def get_stable_hardware_id() -> bytes:
        try:
            if sys.platform == "win32":
                # Using a more reliable way to fetch the UUID
                cmd = "wmic csproduct get uuid"
                uuid = subprocess.check_output(cmd, shell=True).decode().split()
                # Ensure we actually got a UUID and not an error message
                if len(uuid) >= 2:
                    return hashlib.sha256(uuid[1].encode()).digest()
                return hashlib.sha256(b"fallback_id").digest() # Safety fallback
        except Exception:
            return hashlib.sha256(os.environ.get('COMPUTERNAME', 'default').encode()).digest()
        
    @staticmethod
    def derive_key(password: str, salt: bytes, hwid: bytes = None) -> bytes:
        """Derives master key using Argon2id."""
        if isinstance(salt, bytearray): salt = bytes(salt)
        secret = password.encode('utf-8')
        if hwid: secret += bytes(hwid) if isinstance(hwid, bytearray) else hwid
        
        return hash_secret_raw(
            secret=secret, salt=salt, time_cost=ARGON2_TIME, 
            memory_cost=ARGON2_MEM, parallelism=ARGON2_PARALLELISM, 
            hash_len=32, type=Type.ID
        )

    @staticmethod
    def generate_recovery_key() -> str:
        chars = string.ascii_uppercase + string.digits
        raw = ''.join(secrets.choice(chars) for _ in range(24))
        return '-'.join(raw[i:i+4] for i in range(0, len(raw), 4))     
       

# Set appearance
    
ctk.set_appearance_mode("dark")
ctk.set_default_color_theme("blue")

# ========================
# SECURITY CONSTANTS
# ========================
ARGON2_TIME = 6
ARGON2_MEM = 512 * 1024
ARGON2_PARALLELISM = 4
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION = 300

SENSITIVE_VARS = []

# ========================
# ANTI-FORENSIC FUNCTIONS
# ========================

def secure_zero_memory(data):
    """Physically overwrites mutable memory buffers with zeros."""
    if isinstance(data, bytearray):
        for i in range(len(data)):
            data[i] = 0
    elif isinstance(data, (bytes, str)):
        # For immutable types, we can only delete the reference and 
        # hint the Garbage Collector, though this is not a guarantee.
        del data
        gc.collect()

def register_sensitive(var):
    """Register variable for auto-cleanup."""
    SENSITIVE_VARS.append(var)
    return var

def anti_debug_check():
        """Checks for debuggers and kills app if found."""
        if sys.platform == "win32":
            try:
                kernel32 = ctypes.windll.kernel32
                # CheckRemoteDebuggerPresent is more reliable than IsDebuggerPresent
                is_debugger = ctypes.c_bool(False)
                kernel32.CheckRemoteDebuggerPresent(kernel32.GetCurrentProcess(), ctypes.byref(is_debugger))
                
                if is_debugger.value or kernel32.IsDebuggerPresent():
                    print("🚨 DEBUGGER DETECTED! TERMINATING...")
                    # Secure exit
                    emergency_cleanup() 
                    sys.exit(0)
            except:
                pass
  

def emergency_cleanup():
    """Emergency cleanup on exit with secure file wiping."""
    # 1. Zero out Sensitive Variables (using the improved bytearray method)
    for var in SENSITIVE_VARS:
        try:
            secure_zero_memory(var)
        except: pass
    
    # 2. Database Vacuum and Secure Close
    try:
        conn = sqlite3.connect("vault.db")
        conn.execute("VACUUM") 
        conn.close()
    except: pass

    # Optional: If you use temp files for imports/exports, wipe them here
    gc.collect()

atexit.register(emergency_cleanup)

# ========================
# DATABASE FUNCTIONS
# ========================

def init_database():
    """Creates encrypted database with Trusted Device support."""
    conn = sqlite3.connect("vault.db")
    cursor = conn.cursor()
    
    # Secrets Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS secrets (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            site TEXT NOT NULL,
            username TEXT NOT NULL,
            nonce BLOB NOT NULL,
            ciphertext BLOB NOT NULL,
            hmac BLOB NOT NULL,
            created_at TEXT DEFAULT CURRENT_TIMESTAMP,
            accessed_at TEXT
        )
    """)
    
    # Login Attempts
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS login_attempts (
            timestamp TEXT DEFAULT CURRENT_TIMESTAMP,
            success INTEGER
        )
    """)
    
    # NEW: Trusted Devices Table
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS trusted_devices (
            token_hash TEXT PRIMARY KEY,
            expiry_date TEXT NOT NULL
        )
    """)
    
    conn.commit()
    conn.close()
    
# ==========================================

def check_rate_limit() -> bool:
    """Prevents brute-force attacks."""
    conn = sqlite3.connect("vault.db")
    cursor = conn.cursor()
    cutoff_time = (datetime.now() - timedelta(seconds=LOCKOUT_DURATION)).isoformat()
    cursor.execute("""
        SELECT COUNT(*) FROM login_attempts 
        WHERE timestamp > ? AND success = 0
    """, (cutoff_time,))
    failed_attempts = cursor.fetchone()[0]
    conn.close()
    return failed_attempts < MAX_LOGIN_ATTEMPTS

def log_attempt(success: bool):
    """Records login attempt."""
    conn = sqlite3.connect("vault.db")
    cursor = conn.cursor()
    cursor.execute("INSERT INTO login_attempts (success) VALUES (?)", (1 if success else 0,))
    conn.commit()
    conn.close()

# ========================
# GUI APPLICATION
# ========================

def anti_debug_check():
    """Detects debuggers and reverse-engineering tools."""
    if sys.platform == "win32":
        try:
            kernel32 = ctypes.windll.kernel32
            # Check for attached debuggers
            is_debugger = ctypes.c_bool(False)
            kernel32.CheckRemoteDebuggerPresent(kernel32.GetCurrentProcess(), ctypes.byref(is_debugger))
            if is_debugger.value or kernel32.IsDebuggerPresent():
                return False
            return True
        except:
            return True
    return True

class FortressVault(ctk.CTk):
    def __init__(self):
        super().__init__()
        
        # --- 1. WINDOW SETUP ---
        self.title("Secura") 
        self.geometry("1100x700")
        self.minsize(900, 600)
        # 1. Load the internal logo
      
        # --- 2. SET APPLICATION ICON ---
        try:
            icon_path = resource_path("secura_logo.png")
            icon_pil = Image.open(icon_path)
            # 2. Store in self to prevent Garbage Collection
            self.icon_photo = ImageTk.PhotoImage(icon_pil)
            self.iconphoto(False, self.icon_photo) 
            # 3. Force Windows to recognize the unique App ID for the Taskbar
            if sys.platform == "win32":
                myappid = 'kartavya.securavault.v1' 
                ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(myappid)
        except Exception as e:
            pass 

        # --- 3. THEME & SECURITY ---
        ctk.set_appearance_mode("dark")
        
        # ✅ INITIALIZE STATE VARIABLES FIRST
        self.master_key = None
        self.logged_in = False
        self.last_activity = time.time()
        
        # ✅ APPLY SCREEN PROTECTION AFTER WINDOW IS READY
        self.after(100, self.enable_screen_protection)
        
        # ✅ BIND EVENTS
        self.bind_all("<Any-KeyPress>", self.reset_idle_timer)
        self.bind_all("<Any-ButtonPress>", self.reset_idle_timer)
        
        # ✅ START IDLE TIMER (SCHEDULE IT, DON'T CALL IT)
        self.after(10000, self.check_idle_loop)  # Start after 10 seconds
        
        # ✅ SHOW APPROPRIATE SCREEN
        if os.path.exists("vault.config"):
            self.show_login_screen()
        else:
            self.show_setup_screen()
           
    def reset_idle_timer(self, event=None):
        self.last_activity = time.time()

    def get_theme(self):
        return {
            "bg_dark": "#0B0E14",        # Deep Navy
            "bg_panel": "#111827",       # Sidebar
            "accent": "#FF9933",         # 🇮🇳 Saffron
            "accent_hover": "#E68A00",   # Deep Saffron
            "text_main": "#F3F4F6",      # White
            "text_sub": "#9CA3AF",       # Gray
            "input_bg": "#1F2937",       # Inputs
            "border": "#374151",         # Borders
            "danger": "#EF4444",         # Red
            "success": "#10B981"         # Green
        } 
   
   
    def reset_vault(self):
        """Physical deletion of files and exit."""
        try:
            if os.path.exists("vault.db"): os.remove("vault.db")
            if os.path.exists("vault.config"): os.remove("vault.config")
            
            # Show final toast before death
            print("SYSTEM WIPED.")
            sys.exit(0)
        except Exception as e:
            print(f"Wipe failed: {e}")
    # ==========================================
    # 🛡️ SECURITY HELPER (MISSING FUNCTION)
    # ==========================================
    def _protect_window(self, window_ref):
        """
        Applies anti-screenshot protection to ANY window (Main or Popup).
        """
        if sys.platform == "win32":
            try:
                # 1. Get the Windows API handle
                user32 = ctypes.windll.user32
                
                # Force update to ensure the window has a valid ID
                window_ref.update_idletasks()
                
                # Get HWND (Window Handle)
                hwnd = user32.GetParent(window_ref.winfo_id())
                
                # 2. Define Protection Constants
                WDA_MONITOR = 0x00000001              # Black Box (Windows 7+)
                WDA_EXCLUDEFROMCAPTURE = 0x00000011   # Invisible (Windows 10 2004+)
                
                # 3. Apply Protection
                # Try the 'Invisible' method first (cleaner)
                if user32.SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE) == 0:
                     # If that fails (older Windows), use the 'Black Box' method
                     user32.SetWindowDisplayAffinity(hwnd, WDA_MONITOR)
                     
                print(f"🛡️ Protected Window: {window_ref.title()}")
                
            except Exception as e:
                print(f"⚠️ Protection Failed: {e}")
    
    def enable_screen_protection(self):
        """
        Prevents screenshots and screen recording on Windows.
        The window will appear black in screenshots/recordings.
        """
        if sys.platform == "win32":
            try:
                # Constants for Windows API
                WDA_NONE = 0x00000000
                WDA_MONITOR = 0x00000001  # Old method (Black box)
                WDA_EXCLUDEFROMCAPTURE = 0x00000011 # New method (Invisible in capture)

                # Load user32.dll
                user32 = ctypes.windll.user32
                
                # Get window handle (HWND)
                hwnd = user32.GetParent(self.winfo_id())
                
                # Try the newer method first (Windows 10 2004+ / Windows 11)
                # This makes the window invisible to capture but visible to user
                if user32.SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE) == 0:
                    # Fallback to older method (Window appears black in capture)
                    user32.SetWindowDisplayAffinity(hwnd, WDA_MONITOR)
                    
                print("🛡️ Screen Protection Active")
            except Exception as e:
                print(f"⚠️ Failed to enable screen protection: {e}")

    # ==========================================
    # 🚀 MAIN DASHBOARD ENGINE
    # ==========================================
    def show_vault_screen(self):
        """Main Dashboard Screen."""
        self._setup_split_layout() 
        colors = self.get_theme()
        
        # --- SIDEBAR NAV BUTTONS ---
        nav_container = ctk.CTkFrame(self.sidebar_frame, fg_color="transparent")
        nav_container.pack(fill="x", padx=30, pady=20)
        
        self.nav_buttons = {}

        # Helper to create buttons that route through _switch_tab
        def nav_btn(text, val):
            # command=lambda... is CRITICAL for the color change to work
            btn = ctk.CTkButton(nav_container, text=text, height=50, anchor="w", 
                               fg_color="transparent", text_color=colors["text_sub"],
                               hover_color=colors["input_bg"], font=("Arial", 14), 
                               command=lambda: self._switch_tab(val))
            btn.pack(fill="x", pady=4)
            self.nav_buttons[val] = btn
            return btn

        # Define buttons
        nav_btn("Dashboard", "dashboard")
        nav_btn("My Passwords", "passwords")
        nav_btn("🎲 Generator", "generator")
        nav_btn("Audit Logs", "logs")
        nav_btn("Settings", "settings")
                
        # Logout
        ctk.CTkButton(self.sidebar_frame, text="LOCK VAULT", fg_color=colors["danger"], hover_color="#b91c1c",
                     height=45, command=self.lock_vault).pack(side="bottom", fill="x", padx=40, pady=(0, 20))

        # --- CONTENT AREA SETUP ---
        self.content_area = ctk.CTkFrame(self.main_area, fg_color="transparent")
        self.content_area.pack(fill="both", expand=True)
        
        # Load default tab
        self._switch_tab("dashboard")
    
    
    def _create_nav_btn(self, text, value, row):
        """Helper to create consistent menu buttons."""
        colors = self.get_theme()
        btn = ctk.CTkButton(self.nav_bar, text=text, fg_color="transparent", text_color=colors["text_sub"],
                           hover_color=colors["input_bg"], anchor="w", height=45, font=("Arial", 13, "bold"),
                           command=lambda: self._switch_tab(value))
        btn.grid(row=row, column=0, pady=2, padx=10, sticky="ew")
        
        # Store reference to change color later
        if not hasattr(self, 'nav_buttons'): self.nav_buttons = {}
        self.nav_buttons[value] = btn

    def _switch_tab(self, tab_name):
        """
        Handles tab switching AND refreshing.
        Fixes 'Double Dashboard' by forcing UI updates during cleanup.
        """
        try:
            colors = self.get_theme()
            self.active_tab = tab_name
            
            # 1. Update Sidebar Visuals
            if hasattr(self, 'nav_buttons'):
                for name, btn in self.nav_buttons.items():
                    if name == tab_name:
                        btn.configure(fg_color=colors["accent"], text_color="white")
                    else:
                        btn.configure(fg_color="transparent", text_color=colors["text_sub"])
            
            # 2. CLEAR CONTENT AREA (Robust Fix)
            # We explicitly destroy children and force an update
            if hasattr(self, 'content_area'):
                for widget in self.content_area.winfo_children():
                    widget.destroy()
                
                # Force Tkinter to process the deletion immediately
                self.content_area.update_idletasks()
                
            # 3. Load New Content
            if tab_name == "dashboard": self.load_tab_dashboard()
            elif tab_name == "passwords": self.load_tab_passwords()
            elif tab_name == "generator": self.load_tab_generator()
            elif tab_name == "logs": self.load_tab_logs()
            elif tab_name == "settings": self.show_settings()
            
        except Exception as e:
            print(f"Tab switch error: {e}")
    # ==========================================
    # 📊 TAB 1: DASHBOARD (Analytics)
    # ==========================================
    # ==========================================
    # 📊 TAB 1: DASHBOARD (Real-Time Security Analytics)
    # ==========================================
    # ==========================================
    # 📊 TAB 1: DASHBOARD (Security Center)
    # ==========================================
    def load_tab_dashboard(self):
        if not hasattr(self, 'content_area'):
            print("ERROR: content_area not initialized")
            return
    
        if not self.master_key:
            self.show_error("Session expired. Please login again.")
            self.lock_vault()
            return
        
        # Clear existing widgets
        for widget in self.content_area.winfo_children():
            widget.destroy()
        
        colors = self.get_theme()
        
        # 1. Header
        ctk.CTkLabel(self.content_area, text="Security Overview", font=("Roboto Medium", 24), text_color=colors["text_main"]).pack(anchor="w", pady=(30, 20), padx=40)
        
        # 2. Run Analysis
        stats = self._analyze_vault_health()
        
        # 3. Stats Grid
        stats_frame = ctk.CTkFrame(self.content_area, fg_color="transparent")
        stats_frame.pack(fill="x", padx=40)
        
        # Dynamic Color Logic
        score_color = colors["success"]
        if stats['score'] < 50: score_color = colors["danger"]
        elif stats['score'] < 75: score_color = "orange"

        self._create_stat_card(stats_frame, "Total Items", str(stats['total']), colors["accent"])
        self._create_stat_card(stats_frame, "Vault Health", f"{stats['score']}%", score_color)
        self._create_stat_card(stats_frame, "Weak Passwords", str(stats['weak_count']), colors["danger"] if stats['weak_count'] > 0 else colors["success"])

        # 4. "Action Needed" Section
        if stats['weak_sites']:
            # Warning Header
            warn_frame = ctk.CTkFrame(self.content_area, fg_color="transparent")
            warn_frame.pack(fill="x", padx=40, pady=(40, 5))
            ctk.CTkLabel(warn_frame, text="⚠️ Action Required", font=("Roboto Medium", 18), text_color=colors["danger"]).pack(side="left")
            ctk.CTkLabel(warn_frame, text=f"({stats['weak_count']} risks detected)", font=("Arial", 14), text_color="gray").pack(side="left", padx=10)

            # Warning List
            warn_scroll = ctk.CTkScrollableFrame(self.content_area, fg_color="transparent", height=250)
            warn_scroll.pack(fill="x", padx=30, expand=False)
            
            # Loop through weak items (Now includes ID)
            for pid, site, user in stats['weak_sites']:
                row = ctk.CTkFrame(warn_scroll, fg_color=colors["input_bg"], border_width=1, border_color=colors["danger"])
                row.pack(fill="x", pady=4)
                
                # Icon & Name
                ctk.CTkLabel(row, text="🔓", font=("Arial", 16), text_color=colors["danger"]).pack(side="left", padx=15)
                ctk.CTkLabel(row, text=site, font=("Arial", 12, "bold"), text_color="white", width=120, anchor="w").pack(side="left")
                ctk.CTkLabel(row, text=user, font=("Arial", 12), text_color="gray").pack(side="left")
                
                # "Quick Fix" Button (Links to Edit)
                ctk.CTkButton(row, text="⚡ FIX NOW", width=80, height=24, 
                              fg_color=colors["danger"], hover_color="#b91c1c", font=("Arial", 11, "bold"),
                              command=lambda p=pid: self.show_edit_password(p)).pack(side="right", padx=10, pady=8)

                ctk.CTkLabel(row, text="Weak Password", font=("Arial", 10), text_color=colors["danger"]).pack(side="right", padx=10)
        else:
            # Good State
            good_frame = ctk.CTkFrame(self.content_area, fg_color="transparent")
            good_frame.pack(fill="x", padx=40, pady=50)
            ctk.CTkLabel(good_frame, text="✅ All Systems Secure", font=("Roboto Medium", 20), text_color=colors["success"]).pack()
            ctk.CTkLabel(good_frame, text="No weak passwords detected in your vault.", font=("Arial", 12), text_color="gray").pack()
            
            
    def show_password_details(self, pid):
        """Opens a secure, screenshot-protected window to view credentials."""
        try:
            with sqlite3.connect("vault.db") as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT site, username, nonce, ciphertext FROM secrets WHERE id=?", (pid,))
                row = cursor.fetchone()
            
            if not row: return
            site, user, nonce, cipher = row
            
            # Decrypt securely
            pwd_ba = SecurityCore.decrypt_secret(self.master_key, nonce, cipher)
            pwd_str = pwd_ba.decode('utf-8')

            # Create Popup
            view_win = ctk.CTkToplevel(self)
            view_win.title("Secure Credential View")
            view_win.geometry("400x350")
            
            # Apply anti-screenshot protection
            self.after(100, lambda: self._protect_window(view_win))
            
            colors = self.get_theme()
            ctk.CTkLabel(view_win, text=f"Asset: {site}", font=("Arial", 16, "bold")).pack(pady=20)
            
            # Username Display
            ctk.CTkLabel(view_win, text="Username", text_color="gray").pack()
            u_ent = ctk.CTkEntry(view_win, width=250)
            u_ent.insert(0, user)
            u_ent.configure(state="readonly")
            u_ent.pack(pady=5)

            # Password Display (Hidden by default)
            ctk.CTkLabel(view_win, text="Password", text_color="gray").pack(pady=(10,0))
            p_ent = ctk.CTkEntry(view_win, width=250, show="●")
            p_ent.insert(0, pwd_str)
            p_ent.configure(state="readonly")
            p_ent.pack(pady=5)

            def toggle_pass():
                p_ent.configure(show="" if p_ent.cget("show") == "●" else "●")

            ctk.CTkCheckBox(view_win, text="Reveal Secret", command=toggle_pass).pack(pady=10)
            
            def close_and_wipe():
                secure_zero_memory(pwd_ba)
                secure_zero_memory(pwd_str)
                view_win.destroy()

            view_win.protocol("WM_DELETE_WINDOW", close_and_wipe)
            
        except Exception as e:
            self.show_toast(f"Security Alert: {e}", "red")
    
    def _analyze_vault_health(self):
        """Standardized security audit using strict complexity protocols."""
        if not self.master_key:
            return {"total": 0, "weak_count": 0, "score": 100, "weak_sites": []}
        
        try:
            with sqlite3.connect("vault.db", timeout=5.0) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id, site, username, nonce, ciphertext FROM secrets")
                rows = cursor.fetchall()
            
            total, weak, weak_list = len(rows), 0, []
            
            for pid, site, user, nonce, cipher in rows:
                pwd_ba = None
                try:
                    # Decrypt into mutable bytearray for secure analysis
                    pwd_ba = SecurityCore.decrypt_secret(self.master_key, nonce, cipher)
                    p_str = pwd_ba.decode('utf-8')
                    
                    # Audit against Strict Policy
                    is_valid, _ = ValidationHelper.validate_password_strength(p_str)
                    if not is_valid:
                        weak += 1
                        weak_list.append((pid, site, user))
                    
                    secure_zero_memory(p_str)
                finally:
                    if pwd_ba: secure_zero_memory(pwd_ba)
            
            score = int(((total - weak) / total) * 100) if total > 0 else 100
            return {"total": total, "weak_count": weak, "score": score, "weak_sites": weak_list}
        except Exception:
            return {"total": 0, "weak_count": 0, "score": 0, "weak_sites": []}

        
    def _create_stat_card(self, parent, title, value, color):
        card = ctk.CTkFrame(parent, fg_color=self.get_theme()["input_bg"], corner_radius=10)
        card.pack(side="left", expand=True, fill="both", padx=5)
        
        ctk.CTkLabel(card, text=title, font=("Arial", 12, "bold"), text_color="gray").pack(pady=(15, 0))
        ctk.CTkLabel(card, text=value, font=("Arial", 28, "bold"), text_color=color).pack(pady=(5, 15))

    # ==========================================
    # 🔑 TAB 2: PASSWORDS (Zero-Knowledge List)
    # ==========================================



    def load_tab_generator(self):
        """Professional password generator with customization options."""
        # 1. Clear previous content
        for widget in self.content_area.winfo_children():
            widget.destroy()

        colors = self.get_theme()
        
        # Header
        top_bar = ctk.CTkFrame(self.content_area, fg_color="transparent")
        top_bar.pack(fill="x", padx=40, pady=30)
        
        ctk.CTkLabel(top_bar, text="Password Generator", font=("Roboto Medium", 24), 
                    text_color=colors["text_main"]).pack(anchor="w")
        ctk.CTkLabel(top_bar, text="Generate cryptographically secure passwords", 
                    font=("Arial", 12), text_color=colors["text_sub"]).pack(anchor="w")
        
        # Main container
        main_container = ctk.CTkFrame(self.content_area, fg_color="transparent")
        main_container.pack(fill="both", expand=True, padx=40)
        
        # Left panel - Options
        left_panel = ctk.CTkFrame(main_container, fg_color=colors["bg_panel"], 
                                corner_radius=10, width=400)
        left_panel.pack(side="left", fill="y", padx=(0, 20))
        left_panel.pack_propagate(False)
        
        # Title
        ctk.CTkLabel(left_panel, text="⚙️ Configuration", font=("Roboto Medium", 16), 
                    text_color="white").pack(pady=20, padx=20, anchor="w")
        
        # Password Length Slider
        length_frame = ctk.CTkFrame(left_panel, fg_color="transparent")
        length_frame.pack(fill="x", padx=20, pady=(0, 20))
        
        ctk.CTkLabel(length_frame, text="Password Length", font=("Arial", 12, "bold"),
                    text_color=colors["text_sub"]).pack(anchor="w", pady=(0, 5))
        
        length_value_label = ctk.CTkLabel(length_frame, text="16", 
                                        font=("Roboto Mono", 20, "bold"),
                                        text_color=colors["accent"])
        length_value_label.pack(anchor="w", pady=(0, 5))
        
        def update_length(val):
            length_value_label.configure(text=str(int(val)))
        
        length_slider = ctk.CTkSlider(length_frame, from_=8, to=64, number_of_steps=56,
                                    command=update_length, fg_color=colors["input_bg"],
                                    progress_color=colors["accent"])
        length_slider.set(16)
        length_slider.pack(fill="x", pady=(0, 10))
        
        # Checkbox variables
        use_uppercase = ctk.BooleanVar(value=True)
        use_lowercase = ctk.BooleanVar(value=True)
        use_digits = ctk.BooleanVar(value=True)
        use_symbols = ctk.BooleanVar(value=True)
        exclude_ambiguous = ctk.BooleanVar(value=False)

        # Checkboxes
        checkbox_frame = ctk.CTkFrame(left_panel, fg_color="transparent")
        checkbox_frame.pack(fill="x", padx=20)
        
        ctk.CTkCheckBox(checkbox_frame, text="Uppercase (A-Z)", variable=use_uppercase,
                    font=("Arial", 11), text_color=colors["text_main"],
                    fg_color=colors["accent"], hover_color=colors["accent_hover"]).pack(anchor="w", pady=5)
        
        ctk.CTkCheckBox(checkbox_frame, text="Lowercase (a-z)", variable=use_lowercase,
                    font=("Arial", 11), text_color=colors["text_main"],
                    fg_color=colors["accent"], hover_color=colors["accent_hover"]).pack(anchor="w", pady=5)
        
        ctk.CTkCheckBox(checkbox_frame, text="Numbers (0-9)", variable=use_digits,
                    font=("Arial", 11), text_color=colors["text_main"],
                    fg_color=colors["accent"], hover_color=colors["accent_hover"]).pack(anchor="w", pady=5)
        
        ctk.CTkCheckBox(checkbox_frame, text="Symbols (!@#$%)", variable=use_symbols,
                    font=("Arial", 11), text_color=colors["text_main"],
                    fg_color=colors["accent"], hover_color=colors["accent_hover"]).pack(anchor="w", pady=5)

        ctk.CTkCheckBox(checkbox_frame, text="Exclude ambiguous", 
                    variable=exclude_ambiguous,
                    font=("Arial", 11), text_color=colors["text_main"],
                    fg_color=colors["accent"], hover_color=colors["accent_hover"]).pack(anchor="w", pady=5)
        
        # Right panel - Generator output
        right_panel = ctk.CTkFrame(main_container, fg_color=colors["bg_panel"], 
                                corner_radius=10)
        right_panel.pack(side="left", fill="both", expand=True)
        
        # Title
        ctk.CTkLabel(right_panel, text="🔐 Generated Password", font=("Roboto Medium", 16), 
                    text_color="white").pack(pady=20, padx=20, anchor="w")
        
        # Password display
        password_container = ctk.CTkFrame(right_panel, fg_color=colors["input_bg"],
                                        corner_radius=8, border_width=2,
                                        border_color=colors["border"])
        password_container.pack(fill="x", padx=20, pady=(0, 20))
        
        password_display = ctk.CTkTextbox(password_container, height=100, 
                                        font=("Roboto Mono", 18, "bold"),
                                        fg_color="transparent", text_color=colors["accent"],
                                        wrap="word")
        password_display.pack(fill="both", expand=True, padx=15, pady=15)
        password_display.insert("1.0", "Click 'Generate' to create a password")
        password_display.configure(state="disabled")
        
        # Strength indicator
        strength_frame = ctk.CTkFrame(right_panel, fg_color="transparent")
        strength_frame.pack(fill="x", padx=20, pady=(0, 20))
        
        ctk.CTkLabel(strength_frame, text="Strength:", font=("Arial", 11, "bold"),
                    text_color=colors["text_sub"]).pack(side="left")
        
        strength_label = ctk.CTkLabel(strength_frame, text="Not Generated", 
                                    font=("Roboto Medium", 12),
                                    text_color="gray")
        strength_label.pack(side="left", padx=10)
        
        strength_bar = ctk.CTkProgressBar(right_panel, height=8, 
                                        progress_color=colors["success"])
        strength_bar.set(0)
        strength_bar.pack(fill="x", padx=20, pady=(0, 20))
        
        # Entropy display
        entropy_label = ctk.CTkLabel(right_panel, text="Entropy: 0 bits", 
                                    font=("Consolas", 11),
                                    text_color=colors["text_sub"])
        entropy_label.pack(padx=20, pady=(0, 20))
    
        # ----------------------------------------------
        # LOGIC FUNCTIONS (Must be indented inside load_tab_generator)
        # ----------------------------------------------
        def generate_password():
            try:
                length = int(length_slider.get())
                
                # Build character set
                chars = ""
                if use_uppercase.get(): chars += string.ascii_uppercase
                if use_lowercase.get(): chars += string.ascii_lowercase
                if use_digits.get(): chars += string.digits
                if use_symbols.get(): chars += "!@#$%^&*()_+-=[]{}|;:,.<>?"
                
                if not chars:
                    self.show_toast("⚠️ Please select at least one character type", "warning")
                    return
                
                # Exclude ambiguous characters
                if exclude_ambiguous.get():
                    ambiguous = "il1Lo0O"
                    chars = ''.join(c for c in chars if c not in ambiguous)
                    if not chars: chars = string.ascii_letters # Fallback
                
                # Generate password
                password = ''.join(secrets.choice(chars) for _ in range(length))
                
                # Update display
                password_display.configure(state="normal")
                password_display.delete("1.0", "end")
                password_display.insert("1.0", password)
                password_display.configure(state="disabled")
                
                # Calculate strength/Entropy
                import math
                pool_size = len(chars)
                entropy = math.log2(pool_size) * length
                entropy_label.configure(text=f"Entropy: {entropy:.1f} bits")
                
                # Update visual indicator
                if entropy < 50:
                    strength, color, val = "Weak", colors["danger"], 0.3
                elif entropy < 80:
                    strength, color, val = "Moderate", "#f59e0b", 0.6
                else:
                    strength, color, val = "Strong", colors["success"], 1.0
                
                strength_label.configure(text=strength, text_color=color)
                strength_bar.configure(progress_color=color)
                strength_bar.set(val)
                
            except Exception as e:
                self.show_toast(f"Generation Error: {e}", "error")

        def copy_password():
            try:
                pwd = password_display.get("1.0", "end-1c").strip()
                if pwd and "Click 'Generate'" not in pwd:
                    self.copy_to_clipboard(pwd)
                else:
                    self.show_toast("Generate a password first", "warning")
            except: pass

        # ----------------------------------------------
        # BUTTONS (Must be indented inside load_tab_generator)
        # ----------------------------------------------
        button_frame = ctk.CTkFrame(right_panel, fg_color="transparent")
        button_frame.pack(fill="x", padx=20, pady=(0, 20))
        
        ctk.CTkButton(button_frame, text="🎲 Generate Password", height=45,
                    fg_color=colors["accent"], hover_color=colors["accent_hover"],
                    font=("Roboto Medium", 14), command=generate_password).pack(fill="x", pady=(0, 10))
        
        button_row = ctk.CTkFrame(button_frame, fg_color="transparent")
        button_row.pack(fill="x")
        
        ctk.CTkButton(button_row, text="📋 Copy", height=40,
                    fg_color=colors["success"], hover_color="#059669",
                    font=("Arial", 12), command=copy_password).pack(side="left", fill="x", expand=True, padx=(0, 5))
        
        ctk.CTkButton(button_row, text="🔄 Regenerate", height=40,
                    fg_color=colors["bg_dark"], hover_color=colors["input_bg"],
                    font=("Arial", 12), command=generate_password).pack(side="left", fill="x", expand=True, padx=(5, 0))
    
    def _create_password_row(self, parent, pid, site, user):
        colors = self.get_theme()
        
        row = ctk.CTkFrame(parent, fg_color=colors["input_bg"], corner_radius=6)
        row.pack(fill="x", pady=4)
        
        # Icon/Site
        ctk.CTkLabel(row, text="🔐", font=("Arial", 16)).pack(side="left", padx=15)
        ctk.CTkLabel(row, text=site, font=("Roboto Medium", 14), text_color=colors["text_main"], width=150, anchor="w").pack(side="left")
        ctk.CTkLabel(row, text=user, font=("Arial", 12), text_color=colors["text_sub"]).pack(side="left", padx=20)
        
        # Actions 
        actions = ctk.CTkFrame(row, fg_color="transparent")
        actions.pack(side="right", padx=10, pady=10)
        
        # Copy Button
        ctk.CTkButton(actions, text="Copy", width=60, height=25, fg_color=colors["bg_panel"], hover_color=colors["accent"],
                      command=lambda: self.secure_fetch_and_copy(pid)).pack(side="left", padx=2)
                      
        # Edit Button (FIXED: Now calls show_edit_password with the specific PID)
        ctk.CTkButton(actions, text="Edit", width=60, height=25, fg_color=colors["bg_panel"], hover_color=colors["accent"],
                      command=lambda p=pid: self.show_edit_password(p)).pack(side="left", padx=2)
        
        # Delete Button
        ctk.CTkButton(actions, text="🗑️", width=40, height=25, fg_color=colors["danger"], hover_color="red",
                      command=lambda: self.delete_password(pid, site)).pack(side="left", padx=2)
    
    
    # ==========================================
    # ✏️ 2. EDIT FUNCTION (USES THE HELPER ABOVE)
    # ==========================================
    
    def show_edit_password(self, entry_id):
        """High-security interface for modifying or fixing encrypted assets."""
        colors = self.get_theme()
        
        try:
            with sqlite3.connect("vault.db", timeout=5.0) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT site, username, nonce, ciphertext FROM secrets WHERE id = ?", (entry_id,))
                row = cursor.fetchone()
            
            if not row:
                self.show_error("Security Exception: Entry Not Found")
                return
            
            current_site, current_user, old_nonce, old_cipher = row
            # Decrypt into a mutable bytearray for secure wiping
            current_pass_ba = SecurityCore.decrypt_secret(self.master_key, old_nonce, old_cipher)
            current_pass_str = current_pass_ba.decode('utf-8')
            
        except Exception:
            self.show_toast("Security Exception: Operation Aborted", "red")
            return

        # Setup the UI window
        self.edit_win = ctk.CTkToplevel(self)
        self.edit_win.title(f"Vault Editor - {current_site}")
        self.edit_win.geometry("500x700")
        self.edit_win.transient(self)
        self.edit_win.grab_set()
        
        # Apply anti-screenshot protection
        self.after(100, lambda: self._protect_window(self.edit_win))

        bg = ctk.CTkFrame(self.edit_win, fg_color=colors["bg_dark"])
        bg.pack(fill="both", expand=True)
        
        form = ctk.CTkFrame(bg, fg_color="transparent")
        form.pack(fill="both", expand=True, padx=40, pady=20)

        # UI Field Builder
        def add_field(label, value, is_pass=False):
            ctk.CTkLabel(form, text=label, font=("Arial", 11, "bold"), text_color="gray").pack(anchor="w", pady=(10, 0))
            entry = ctk.CTkEntry(form, height=40, fg_color=colors["input_bg"], border_color=colors["border"])
            entry.insert(0, value)
            if is_pass: entry.configure(show="●")
            entry.pack(fill="x", pady=(5, 10))
            return entry

        self.edit_site_ent = add_field("SERVICE / APPLICATION", current_site)
        self.edit_user_ent = add_field("USERNAME / ID", current_user)
        
        # --- PASSWORD SECTION ---
        ctk.CTkLabel(form, text="SECRET PASSWORD", font=("Arial", 11, "bold"), text_color="gray").pack(anchor="w", pady=(10, 0))
        pass_row = ctk.CTkFrame(form, fg_color="transparent")
        pass_row.pack(fill="x", pady=(5, 10))
        
        self.edit_pass_ent = ctk.CTkEntry(pass_row, height=40, show="●", fg_color=colors["input_bg"], border_color=colors["border"])
        self.edit_pass_ent.insert(0, current_pass_str)
        self.edit_pass_ent.pack(side="left", fill="x", expand=True, padx=(0, 10))

        # Secure Generator Button
        def generate_fix():
            chars = string.ascii_letters + string.digits + "!@#$%^&*"
            new_pwd = ''.join(secrets.choice(chars) for _ in range(24))
            self.edit_pass_ent.delete(0, 'end')
            self.edit_pass_ent.insert(0, new_pwd)
            self.edit_pass_ent.configure(show="") # Show generated pass immediately
            btn_toggle.configure(text="HIDE SENSITIVE DATA", fg_color=colors["danger"])

        ctk.CTkButton(pass_row, text="🎲", width=40, height=40, command=generate_fix, 
                     fg_color=colors["bg_panel"], hover_color=colors["accent"]).pack(side="right")

        # Visibility Toggle
        def toggle_all():
            if self.edit_pass_ent.cget("show") == "●":
                self.edit_pass_ent.configure(show="")
                btn_toggle.configure(text="HIDE SENSITIVE DATA", fg_color=colors["danger"])
            else:
                self.edit_pass_ent.configure(show="●")
                btn_toggle.configure(text="SHOW ALL DETAILS", fg_color=colors["accent"])

        btn_toggle = ctk.CTkButton(form, text="SHOW ALL DETAILS", height=35, command=toggle_all)
        btn_toggle.pack(fill="x", pady=10)

        # Save Action with Protocol Messages
        def save_changes():
            new_site = self.edit_site_ent.get().strip()
            new_user = self.edit_user_ent.get().strip()
            new_pass = self.edit_pass_ent.get()
            
            try:
                # Duplicate Check for Modified Credentials
                with sqlite3.connect("vault.db", timeout=5.0) as conn:
                    cursor = conn.cursor()
                    cursor.execute("SELECT id FROM secrets WHERE site = ? AND username = ? AND id != ?", 
                                 (new_site, new_user, entry_id))
                    if cursor.fetchone():
                        self.show_toast("Security Exception: Entry Already Exists", "red")
                        return

                # Re-encrypt with GCM
                new_nonce, new_cipher = SecurityCore.encrypt_secret(self.master_key, new_pass)
                
                with sqlite3.connect("vault.db", timeout=5.0) as conn:
                    conn.execute("""
                        UPDATE secrets SET site=?, username=?, nonce=?, ciphertext=?, hmac=? WHERE id=?
                    """, (new_site, new_user, sqlite3.Binary(new_nonce), 
                          sqlite3.Binary(new_cipher), sqlite3.Binary(b""), entry_id))
                
                secure_zero_memory(current_pass_ba)
                self.edit_win.destroy()
                self._switch_tab("passwords")
                self.show_toast("Cryptographic Update Complete: Entry Modified", "green")
                
            except Exception:
                self.show_toast("Security Exception: Operation Aborted", "red")
            
        ctk.CTkButton(form, text="CONFIRM MODIFICATION", height=50, fg_color=colors["success"], 
                     font=("Arial", 13, "bold"), command=save_changes).pack(side="bottom", fill="x", pady=20)
    
    def secure_fetch_and_copy(self, pid):
        """
        Fetches encrypted data securely ON DEMAND.
        Data does not exist in the GUI layer until this button is clicked.
        """
        try:
            with sqlite3.connect("vault.db",timeout=5.0) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT nonce, ciphertext, hmac FROM secrets WHERE id = ?", (pid,))
                row = cursor.fetchone()
            
            if row:
                nonce, cipher, mac = row
                pwd_ba = SecurityCore.decrypt_secret(self.master_key, nonce, cipher)
                password = pwd_ba.decode('utf-8')
                
                # Copy using your existing secure clipboard method
                self.copy_to_clipboard(password)
                
                # Immediate variable cleanup
                secure_zero_memory(password)
                del password
                
        except Exception as e:
            self.show_error(f"Decryption Failed: {e}")
    
    
    def check_idle_loop(self):
        """Checks every 10 seconds if user is idle for > 5 minutes."""
        try:
            # Only check if logged in
            if self.logged_in and self.master_key:
                idle_seconds = time.time() - self.last_activity
                
                if idle_seconds > 300:  # 5 minutes = 300 seconds
                    print("💤 Auto-locking due to inactivity...")
                    self.lock_vault()
                    self.show_toast("🔒 Vault auto-locked due to inactivity", "warning", duration=3000)
                    return  # Don't reschedule after locking
            
            # ✅ Schedule next check (every 10 seconds)
            self.after(10000, self.check_idle_loop)
            
        except Exception as e:
            print(f"Idle check error: {e}")
            # Still reschedule even if there's an error
            self.after(10000, self.check_idle_loop)
                
    def secure_clipboard_copy(self, text):
        """Copies text and verifies it wasn't hijacked immediately."""
        try:
            import pyperclip
            pyperclip.copy(text)
            
            # Verification Check
            time.sleep(0.1)
            if pyperclip.paste() != text:
                self.show_toast("⚠️ CLIPBOARD HIJACK DETECTED!", "red")
                # Immediate counter-measure: clear it
                pyperclip.copy("")
            else:
                self.show_toast("✅ Copied Securely (Auto-clear in 30s)", "green")
                
            # Start the auto-clear timer
            threading.Thread(target=self._clear_clipboard_thread, daemon=True).start()
        except:
            self.show_error("Clipboard access failed")

    def _clear_clipboard_thread(self):
        time.sleep(30)
        import pyperclip
        try:
            # Only clear if it's still our sensitive data (user might have copied something else since)
            # This is a bit tricky to check securely without re-exposing data, 
            # so we blindly clear for safety or check length.
            pyperclip.copy("") 
        except: pass
        
        
    
    
    # ==========================================
    # 📜 TAB 3: AUDIT LOGS (Intrusion Detection)
    # ==========================================
    def load_tab_logs(self):
        # 1. Clear Content (This ensures it is separate)
        for widget in self.content_area.winfo_children():
            widget.destroy()

        colors = self.get_theme()
        
        # Header
        top_bar = ctk.CTkFrame(self.content_area, fg_color="transparent")
        top_bar.pack(fill="x", padx=40, pady=30)
        ctk.CTkLabel(top_bar, text="Access Audit Logs", font=("Roboto Medium", 24), text_color=colors["text_main"]).pack(anchor="w")
        ctk.CTkLabel(top_bar, text="Monitor all authentication attempts.", font=("Arial", 12), text_color=colors["text_sub"]).pack(anchor="w")

        # Log Console Container
        console = ctk.CTkScrollableFrame(self.content_area, fg_color="#0f0f12", corner_radius=6, border_width=1, border_color="#333")
        console.pack(fill="both", expand=True, padx=40, pady=(0, 40))
        
        # Fetch Data
        try:
            conn = sqlite3.connect("vault.db")
            cursor = conn.cursor()
            # Get last 50 events, newest first
            cursor.execute("SELECT timestamp, success FROM login_attempts ORDER BY timestamp DESC LIMIT 50")
            logs = cursor.fetchall()
            conn.close()
        except:
            logs = []

        if not logs:
            ctk.CTkLabel(console, text="No logs available.", text_color="gray").pack(pady=20)
            return

        # Render Logs looks like a terminal
        for ts, success in logs:
            row = ctk.CTkFrame(console, fg_color="transparent", height=30)
            row.pack(fill="x", pady=2)
            
            # Timestamp (Gray)
            ctk.CTkLabel(row, text=f"[{ts}]", font=("Consolas", 11), text_color="gray").pack(side="left", padx=(10, 10))
            
            # Status
            if success:
                status_txt = "ACCESS_GRANTED"
                status_col = colors["success"]
            else:
                status_txt = "ACCESS_DENIED "  # Extra space for alignment
                status_col = colors["danger"]
                
            ctk.CTkLabel(row, text=status_txt, font=("Consolas", 11, "bold"), text_color=status_col).pack(side="left")
            
            # Detail
            msg = "User authenticated successfully" if success else "Invalid credentials or hardware mismatch"
            ctk.CTkLabel(row, text=f":: {msg}", font=("Consolas", 11), text_color="gray").pack(side="left", padx=10)
        
    # ==========================================
    # ➕ ADD NEW ENTRY (MODAL)
    # ==========================================
    def show_add_password(self):
        """
        Opens a dark, professional modal to add a new secret.
        """
        self.add_win = ctk.CTkToplevel(self)
        colors = self.get_theme()
        
        # 1. SETUP WINDOW
        self.add_win = ctk.CTkToplevel(self)
        self.add_win.title("Encrypt New Asset")
        self.add_win.geometry("450x550")
        self.add_win.resizable(False, False)
        
        # Make it Modal (Blocks main app)
        self.add_win.transient(self)
        self.add_win.grab_set()
        self.add_win.after(10, self.add_win.focus_force)
        self.after(100, lambda: self._protect_window(self.add_win))
        
        # 2. MAIN BACKGROUND
        bg = ctk.CTkFrame(self.add_win, fg_color=colors["bg_dark"], corner_radius=0)
        bg.pack(fill="both", expand=True)
        
        # 3. PROFESSIONAL HEADER
        header = ctk.CTkFrame(bg, fg_color=colors["bg_panel"], height=80, corner_radius=0)
        header.pack(fill="x")
        header.pack_propagate(False) # Force height
        
        # Icon & Text in Header
        title_frame = ctk.CTkFrame(header, fg_color="transparent")
        title_frame.place(relx=0.5, rely=0.5, anchor="center")
        
        ctk.CTkLabel(title_frame, text="🔐", font=("Arial", 24)).pack(side="left", padx=(0, 10))
        
        text_frame = ctk.CTkFrame(title_frame, fg_color="transparent")
        text_frame.pack(side="left")
        
        ctk.CTkLabel(text_frame, text="NEW SECURE ENTRY", font=("Roboto Medium", 16), text_color="white").pack(anchor="w")
        ctk.CTkLabel(text_frame, text="Enter details to encrypt", font=("Arial", 11), text_color=colors["text_sub"]).pack(anchor="w")

        # 4. FORM CONTAINER
        form = ctk.CTkFrame(bg, fg_color="transparent")
        form.pack(fill="both", expand=True, padx=30, pady=25)
        
        self.new_entry_inputs = {}
        
        # Helper for styled inputs
        def add_field(label, key):
            ctk.CTkLabel(form, text=label, font=("Arial", 10, "bold"), text_color=colors["text_sub"]).pack(anchor="w", pady=(0, 5))
            ent = ctk.CTkEntry(form, height=45, fg_color=colors["input_bg"], 
                             border_color=colors["border"], border_width=1,
                             text_color="white", font=("Arial", 13))
            ent.pack(fill="x", pady=(0, 15))
            self.new_entry_inputs[key] = ent
            return ent

        # Site & Username Fields
        site_entry = add_field("SERVICE / WEBSITE", "site")
        add_field("USERNAME / ID", "username")
        
        # --- PASSWORD SECTION (Redesigned) ---
        ctk.CTkLabel(form, text="SECRET PASSWORD", font=("Arial", 10, "bold"), text_color=colors["text_sub"]).pack(anchor="w", pady=(0, 5))
        
        # Container for Input + Button
        pass_group = ctk.CTkFrame(form, fg_color="transparent")
        pass_group.pack(fill="x")
        
        self.pass_entry = ctk.CTkEntry(pass_group, height=45, fg_color=colors["input_bg"], 
                                     border_color=colors["border"], border_width=1,
                                     text_color="white", font=("Arial", 13))
        self.pass_entry.pack(side="left", fill="x", expand=True, padx=(0, 10))
        
        # Generator Button (Square, Icon-only style)
        def generate_modal_pass():
            chars = string.ascii_letters + string.digits + "!@#$%^&*"
            pwd = ''.join(secrets.choice(chars) for _ in range(24))
            self.pass_entry.delete(0, 'end')
            self.pass_entry.insert(0, pwd)
            self._update_strength_meter(None)

        ctk.CTkButton(pass_group, text="🎲", width=45, height=45, 
                     fg_color=colors["bg_panel"], hover_color=colors["accent"], 
                     font=("Arial", 20),
                     command=generate_modal_pass).pack(side="right")

        # Strength Meter (Thin Strip)
        self.strength_bar = ctk.CTkProgressBar(form, height=3, progress_color=colors["danger"])
        self.strength_bar.set(0)
        self.strength_bar.pack(fill="x", pady=(5, 20))
        
        self.pass_entry.bind("<KeyRelease>", self._update_strength_meter)

        # 5. FOOTER ACTIONS
        # Spacer
        ctk.CTkLabel(form, text="", height=10).pack()
        
        ctk.CTkButton(form, text="ENCRYPT & SAVE", height=50, 
                     fg_color=colors["success"], hover_color="#059669",
                     font=("Roboto Medium", 13), 
                     corner_radius=6,
                     command=self._save_new_entry).pack(side="bottom", fill="x")

        # Focus first field
        site_entry.focus()
    
    def _generate_for_modal(self):
        """Generates a cryptographically strong 24-char password."""
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        pwd = ''.join(secrets.choice(chars) for _ in range(24))
        
        self.pass_entry.delete(0, 'end')
        self.pass_entry.insert(0, pwd)
        self._update_strength_meter(None)
        
    def _generate_for_edit(self):
        """Generates a strong password specifically for the edit window."""
        chars = string.ascii_letters + string.digits + "!@#$%^&*"
        pwd = ''.join(secrets.choice(chars) for _ in range(24))
        
        # Insert into the Edit Window's password field
        self.edit_pass_entry.delete(0, 'end')
        self.edit_pass_entry.insert(0, pwd)
        # Ensure it is visible so the user can see what was generated
        self.edit_pass_entry.configure(show="") 
        self.btn_eye.configure(text="Hide") # Update the toggle button text if you have one

    def _update_strength_meter(self, event):
        """Visual feedback for password strength."""
        pwd = self.pass_entry.get()
        score = 0
        if len(pwd) > 8: score += 0.2
        if len(pwd) > 12: score += 0.2
        if any(c.isupper() for c in pwd): score += 0.2
        if any(c.isdigit() for c in pwd): score += 0.2
        if any(c in "!@#$%^&*" for c in pwd): score += 0.2
        
        colors = self.get_theme()
        self.strength_bar.set(score)
        
        if score < 0.4: self.strength_bar.configure(progress_color=colors["danger"])
        elif score < 0.8: self.strength_bar.configure(progress_color="orange")
        else: self.strength_bar.configure(progress_color=colors["success"])

    def start_session_monitor(self):
        """Starts a background thread to detect unauthorized debugging during the session."""
        def monitor_loop():
            while self.logged_in:
                if sys.platform == "win32":
                    try:
                        kernel32 = ctypes.windll.kernel32
                        is_debugger = ctypes.c_bool(False)
                        kernel32.CheckRemoteDebuggerPresent(kernel32.GetCurrentProcess(), ctypes.byref(is_debugger))
                        
                        if is_debugger.value or kernel32.IsDebuggerPresent():
                            # Force immediate lock and memory wipe
                            self.after(0, self.lock_vault)
                            break
                    except:
                        pass
                time.sleep(2)

        monitor_thread = threading.Thread(target=monitor_loop, daemon=True)
        monitor_thread.start()
    
    def _save_new_entry(self):
        """Encrypts and saves to DB with Strict Enforcement and Duplicate Prevention."""
        site = self.new_entry_inputs["site"].get().strip()
        user = self.new_entry_inputs["username"].get().strip()
        pwd = self.pass_entry.get()
        
        # 1. STRICT ENFORCEMENT POLICY
        # Enforces: 12+ chars, Uppercase, Lowercase, Number, and Symbol
        is_strong, error_msg = ValidationHelper.validate_password_strength(pwd)
        if not is_strong:
            self.show_toast(f"Security Policy Violation: {error_msg}", "red")
            return

        if not site:
            self.show_toast("Security Exception: Site Name Required", "red")
            return

        try:
            # 2. DUPLICATE PREVENTION
            with sqlite3.connect("vault.db", timeout=5.0) as conn:
                cursor = conn.cursor()
                cursor.execute("SELECT id FROM secrets WHERE site = ? AND username = ?", (site, user))
                if cursor.fetchone():
                    self.show_toast("Security Exception: Duplicate Entry Detected", "red")
                    return
            
            # 3. ENCRYPT (Native AES-GCM Flow)
            nonce, ciphertext_with_tag = SecurityCore.encrypt_secret(self.master_key, pwd)

            # 4. SAVE TO DATABASE
            with sqlite3.connect("vault.db", timeout=5.0) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO secrets (site, username, nonce, ciphertext, hmac) 
                    VALUES (?, ?, ?, ?, ?)
                """, (site, user, sqlite3.Binary(nonce), sqlite3.Binary(ciphertext_with_tag), sqlite3.Binary(b"")))
                conn.commit()
            
            # 5. Anti-Forensic Memory Sanitization
            secure_zero_memory(pwd)
            self.add_win.destroy()
            self.show_toast("Vault Synchronized: Asset Encrypted Successfully", "green")
            
            if hasattr(self, 'active_tab'):
                self._switch_tab(self.active_tab)
            
        except Exception:
            self.show_toast("Security Exception: Operation Aborted", "red")        
    
    # ==========================================
    # 🖥️ RESPONSIVE SCREEN BUILDER
    # ==========================================
    # ==========================================
    # 🖥️ RESPONSIVE SCREEN BUILDER (FIXED)
    # ==========================================
    def _setup_split_layout(self):
        """Creates the Sidebar and Main Area with personalized developer branding."""
        self.clear_window()
        colors = self.get_theme()
        
        # Grid Configuration: Sidebar (Fixed) + Content (Fluid)
        self.grid_columnconfigure(0, minsize=420, weight=0)
        self.grid_columnconfigure(1, weight=1)
        self.grid_rowconfigure(0, weight=1)

        # --- SIDEBAR ---
        self.sidebar_frame = ctk.CTkFrame(self, fg_color=colors["bg_panel"], corner_radius=0, width=420)
        self.sidebar_frame.grid(row=0, column=0, sticky="nsew")
        self.sidebar_frame.grid_propagate(False)
        
        # --- BRANDING HEADER ---
        brand_box = ctk.CTkFrame(self.sidebar_frame, fg_color="transparent")
        brand_box.pack(fill="x", pady=(80, 30), padx=40)
        
        header_row = ctk.CTkFrame(brand_box, fg_color="transparent")
        header_row.pack(anchor="w")

        # [A] LOGO DISPLAY
        try:
            pil_image = Image.open(resource_path("secura_logo.png"))
            logo_img = ctk.CTkImage(light_image=pil_image, dark_image=pil_image, size=(100, 100))
            ctk.CTkLabel(header_row, image=logo_img, text="").pack(side="left", padx=(0, 25))
        except:
            pass

        # [B] TEXT COLUMN
        text_col = ctk.CTkFrame(header_row, fg_color="transparent")
        text_col.pack(side="left")
        
        ctk.CTkLabel(text_col, text="Secura", font=("Roboto Medium", 42), text_color="white").pack(anchor="w")
        ctk.CTkLabel(text_col, text="Your Secure Vault", font=("Arial", 16), text_color=colors["accent"]).pack(anchor="w")

        # Divider
        ctk.CTkFrame(self.sidebar_frame, height=2, fg_color=colors["border"]).pack(fill="x", padx=40, pady=(0, 20))
        
        # --- CUSTOM DEVELOPER FOOTER ---
        footer_container = ctk.CTkFrame(self.sidebar_frame, fg_color="transparent")
        footer_container.pack(side="bottom", pady=30, fill="x")

        ctk.CTkLabel(footer_container, text="Developed with ❤ by Kartavya", 
                    font=("Arial", 13, "bold"), text_color="white").pack()

        # GitHub Link
        import webbrowser
        github_url = "https://github.com/Kartavyajoshi"
        github_lbl = ctk.CTkLabel(footer_container, text="🔗 View on GitHub", 
                                 font=("Arial", 11), text_color=colors["accent"], cursor="hand2")
        github_lbl.pack(pady=(5, 0))
        github_lbl.bind("<Button-1>", lambda e: webbrowser.open_new(github_url))

        # Original Location/Date Label
        ctk.CTkLabel(footer_container, text="© 2026 Kartavya Joshi", 
                    font=("Arial", 10), text_color="gray").pack(pady=(10, 0))

        # --- MAIN AREA ---
        self.main_area = ctk.CTkFrame(self, fg_color=colors["bg_dark"], corner_radius=0)
        self.main_area.grid(row=0, column=1, sticky="nsew")

        # Centering container for Login/Register forms
        self.form_frame = ctk.CTkFrame(self.main_area, fg_color="transparent")
        self.form_frame.place(relx=0.5, rely=0.5, anchor="center", relwidth=0.6)
    # ==========================================
    # 🔑 PROFESSIONAL LOGIN SCREEN
    # ==========================================
    def show_login_screen(self):
        self._setup_split_layout()
        colors = self.get_theme()
        
        # Header
        ctk.CTkLabel(self.form_frame, text="Welcome Back", font=("Roboto Medium", 32), text_color="white").pack(anchor="w", pady=(0, 5))
        ctk.CTkLabel(self.form_frame, text="Verify identity to access the vault.", font=("Arial", 14), text_color="gray").pack(anchor="w", pady=(0, 30))

        # 1. Master Password
        ctk.CTkLabel(self.form_frame, text="MASTER PASSWORD", font=("Arial", 11, "bold"), text_color=colors["accent"]).pack(anchor="w", pady=(0, 5))
        self.pass_entry = ctk.CTkEntry(self.form_frame, placeholder_text="Enter passphrase...", show="●", height=50, 
                                     border_color=colors["border"], fg_color=colors["input_bg"])
        self.pass_entry.pack(fill="x", pady=(0, 20))
        
        # 2. MFA Code
        ctk.CTkLabel(self.form_frame, text="AUTHENTICATOR CODE", font=("Arial", 11, "bold"), text_color=colors["accent"]).pack(anchor="w", pady=(0, 5))
        self.mfa_entry = ctk.CTkEntry(self.form_frame, placeholder_text="000 000", justify="center", height=50, 
                                    font=("Roboto Mono", 18), border_color=colors["border"], fg_color=colors["input_bg"])
        self.mfa_entry.pack(fill="x", pady=(0, 10))
        
        # Status
        self.login_status = ctk.CTkLabel(self.form_frame, text="", text_color=colors["danger"])
        self.login_status.pack(pady=5)
        
        # Unlock Button (Saffron)
        ctk.CTkButton(self.form_frame, text="UNLOCK SECURA", height=55, fg_color=colors["accent"], hover_color=colors["accent_hover"],
                     font=("Roboto Medium", 15), command=self._perform_login_logic).pack(fill="x", pady=20)
        
        # Reset
        ctk.CTkButton(self.form_frame, text="Reset Vault", fg_color="transparent", text_color="gray", 
                     hover_color=colors["input_bg"], command=self.reset_vault).pack(fill="x")

        self.pass_entry.bind("<Return>", lambda e: self._perform_login_logic())
        self.mfa_entry.bind("<Return>", lambda e: self._perform_login_logic())
    
    # ==========================================
    # 📝 PROFESSIONAL REGISTER SCREEN
    # ==========================================
    def show_setup_screen(self):
        self._setup_split_layout()
        colors = self.get_theme()
        
        # Header
        ctk.CTkLabel(self.form_frame, text="Initialize Vault", font=("Roboto Medium", 28), text_color=colors["text_main"]).pack(anchor="w", pady=(0, 5))
        ctk.CTkLabel(self.form_frame, text="Configure hardware binding and master encryption.", font=("Arial", 12), text_color=colors["text_sub"]).pack(anchor="w", pady=(0, 30))

        # Inputs
        self._create_input_group(self.form_frame, "CREATE PASSWORD", "Min 12 characters...", is_password=True, ref="reg_p1")
        self._create_input_group(self.form_frame, "CONFIRM PASSWORD", "Repeat password...", is_password=True, ref="reg_p2")

        # Recovery Key Preview
        temp_key = SecurityCore.generate_recovery_key()
        self.generated_recovery_key = temp_key # Store for logic
        
        ctk.CTkLabel(self.form_frame, text="RECOVERY KEY (SAVE THIS)", font=("Arial", 10, "bold"), text_color=colors["accent"]).pack(anchor="w", pady=(15, 5))
        rec_entry = ctk.CTkEntry(self.form_frame, height=45, corner_radius=8, border_width=1,
                               fg_color=colors["input_bg"], border_color=colors["accent"], text_color=colors["accent"])
        rec_entry.insert(0, temp_key)
        rec_entry.configure(state="readonly")
        rec_entry.pack(fill="x")

        # Status
        self.reg_status = ctk.CTkLabel(self.form_frame, text="", text_color=colors["danger"], font=("Arial", 12))
        self.reg_status.pack(pady=(10, 0), anchor="w")

        # Button
        btn = ctk.CTkButton(self.form_frame, text="ENCRYPT & INITIALIZE", height=55, corner_radius=8,
                           fg_color=colors["success"], hover_color="#059669",
                           font=("Roboto Medium", 14), command=self._perform_register_logic)
        btn.pack(fill="x", pady=30)

    # ==========================================
    # 🛠️ HELPER: STYLED INPUTS
    # ==========================================
    def _create_input_group(self, parent, label_text, placeholder, is_password, ref):
        """Creates a modern, labelled input field and stores it in self.inputs"""
        if not hasattr(self, 'inputs'): self.inputs = {}
        
        colors = self.get_theme()
        
        ctk.CTkLabel(parent, text=label_text, font=("Arial", 10, "bold"), text_color=colors["text_sub"]).pack(anchor="w", pady=(0, 5))
        
        entry = ctk.CTkEntry(parent, placeholder_text=placeholder, height=50, corner_radius=8,
                           border_width=1, border_color=colors["border"], fg_color=colors["input_bg"],
                           text_color=colors["text_main"], placeholder_text_color="gray40",
                           show="●" if is_password else "")
        entry.pack(fill="x", pady=(0, 15))
        
        self.inputs[ref] = entry

    # ==========================================
    # 🧠 LOGIC CONNECTORS
    # ==========================================
    def _perform_login_logic(self):
        # 1. Gather Inputs
        password = self.pass_entry.get()
        mfa_code = self.mfa_entry.get().strip().replace(" ", "")
        
        
        # Validate inputs
        if not password:
            self.login_status.configure(text="⚠️ Password is required")
            self.pass_entry.focus()
            return
        
        if not mfa_code:
            self.login_status.configure(text="⚠️ MFA code is required")
            self.mfa_entry.focus()
            return
        
        if len(mfa_code) != 6 or not mfa_code.isdigit():
            self.login_status.configure(text="⚠️ MFA code must be 6 digits")
            self.mfa_entry.delete(0, 'end')
            self.mfa_entry.focus()
            return
        
        if not check_rate_limit():
            self.login_status.configure(text="🛑 Account locked due to failed attempts")
            self.pass_entry.configure(state="disabled")
            self.mfa_entry.configure(state="disabled")
            return
        
        # 2. Security Checks
        if not password or not mfa_code:
            self.login_status.configure(text="⚠️ Please enter both Password and Code.")
            return

        if not check_rate_limit():
            self.login_status.configure(text="⛔ SECURITY LOCKOUT: Too many failures.")
            return

        try:
            with open("vault.config", "r") as f: config = json.load(f)
            
            # 3. Verify Password First (Argon2)
            salt = bytes.fromhex(config["master_salt"])
            hwid = SecurityCore.get_stable_hardware_id()
            key = SecurityCore.derive_key(password, salt, hwid)
            
            stored_hash = bytes.fromhex(config["verification_hash"])
            computed = hashlib.pbkdf2_hmac('sha256', key, b'verification', 100000)
            
            if hmac.compare_digest(stored_hash, computed):
                # Password is Valid -> Now Check MFA
                if config.get("use_totp"):
                    totp = pyotp.TOTP(config["totp_secret"])
                    if totp.verify(mfa_code, valid_window=1):
                        # --- SUCCESS ---
                        self.master_key = key
                        log_attempt(True)  # <--- FIXED: Only sends True
                        self.complete_login()
                    else:
                        # Password Good, MFA Bad
                        log_attempt(False) # <--- FIXED: Only sends False
                        self.login_status.configure(text="❌ Invalid Authenticator Code")
                        self.mfa_entry.delete(0, 'end')
                else:
                    # Legacy fallback
                    self.master_key = key
                    self.complete_login()
            else:
                # Password Bad
                log_attempt(False) # <--- FIXED: Only sends False
                self.login_status.configure(text="❌ Invalid Credentials")
                self.pass_entry.delete(0, 'end')
                
        except Exception as e:
            self.login_status.configure(text=f"⚠️ System Error: {e}")
        
   
     
    def show_mfa_login_popup(self, secret):
        """Shows blocking MFA popup. Required for EVERY login."""
        dialog = ctk.CTkToplevel(self)
        dialog.title("2FA Verification")
        dialog.geometry("400x300")
        dialog.transient(self)
        dialog.grab_set()
        
        # Apply Screen Protection
        self.after(100, lambda: self._protect_window(dialog))
        
        colors = self.get_theme()
        bg = ctk.CTkFrame(dialog, fg_color=colors["bg_dark"])
        bg.pack(fill="both", expand=True)

        ctk.CTkLabel(bg, text="🔐 Code Required", font=("Roboto Medium", 18), text_color="white").pack(pady=(30, 10))
        ctk.CTkLabel(bg, text="Enter code from your authenticator.", font=("Arial", 12), text_color="gray").pack(pady=(0, 20))

        # Code Entry
        code_entry = ctk.CTkEntry(bg, placeholder_text="000 000", justify="center", 
                                font=("Roboto Mono", 20), height=50, width=200)
        code_entry.pack(pady=10)
        code_entry.focus()

        status_lbl = ctk.CTkLabel(bg, text="", text_color=colors["danger"])
        status_lbl.pack()

        def verify():
            code = code_entry.get().replace(" ", "")
            totp = pyotp.TOTP(secret)
            
            if totp.verify(code, valid_window=0):
                # SUCCESS: Commit the key
                self.master_key = self.temp_login_key
                del self.temp_login_key # Clear temp storage
                
                dialog.destroy()
                self.complete_login()
            else:
                # FAIL: Log it and check lockout
                log_attempt(False)
                status_lbl.configure(text="❌ Invalid Code")
                code_entry.delete(0, 'end')
                code_entry.configure(border_color=colors["danger"])
                
                if not check_rate_limit():
                    dialog.destroy()
                    self.login_status.configure(text="⛔ LOCKED: Too many failed MFA attempts.")

        ctk.CTkButton(bg, text="VERIFY", width=200, height=45, fg_color=colors["accent"], command=verify).pack(pady=20)
        code_entry.bind("<Return>", lambda e: verify())
    
    def complete_login(self):
        """Finalizes login and switches screen."""
        self.logged_in = True
        
        # FIXED: Clear the new specific entry fields instead of the old dictionary
        self.start_session_monitor()
        try:
            if hasattr(self, 'pass_entry'):
                self.pass_entry.delete(0, 'end')
            if hasattr(self, 'mfa_entry'):
                self.mfa_entry.delete(0, 'end')
        except:
            pass

        self.show_vault_screen()

    def _perform_register_logic(self):
        """
        Step 1: STRICT Password Validation & Transition to MFA.
        """
        p1 = self.inputs["reg_p1"].get()
        p2 = self.inputs["reg_p2"].get()
        
        # 1. Basic Match Check
        if p1 != p2:
            self.reg_status.configure(text="❌ Passwords do not match")
            return

        # 2. Advanced Strength Enforcement
        # Must have: 12+ chars, 1 Upper, 1 Lower, 1 Digit, 1 Symbol
        error_msg = self._check_password_strength(p1)
        if error_msg:
            self.reg_status.configure(text=f"⚠️ {error_msg}")
            return
            
        # 3. Success -> Generate MFA
        try:
            temp_mfa_secret = pyotp.random_base32()
            self.show_mfa_setup(p1, temp_mfa_secret)
        except Exception as e:
            self.reg_status.configure(text=f"System Error: {e}")

    def _check_password_strength(self, password):
        """Returns None if secure, or an error string if weak."""
        if len(password) < 12:
            return "Password must be 12+ characters"
        if not any(c.isupper() for c in password):
            return "Must include an UPPERCASE letter"
        if not any(c.islower() for c in password):
            return "Must include a lowercase letter"
        if not any(c.isdigit() for c in password):
            return "Must include a Number (0-9)"
        if not any(c in "!@#$%^&*()_+-=[]{}|;:,.<>?" for c in password):
            return "Must include a Symbol (!@#$)"
        return None
          
    def show_mfa_setup(self, password, mfa_secret):
        """
        Step 2: Seamless MFA Screen (Integrated into Main Layout).
        No pop-ups. Uses the standard split-screen design.
        """
        # 1. Re-draw the standard layout (Sidebar + Content)
        self._setup_split_layout()
        colors = self.get_theme()
        
        # We will add content to 'self.form_frame' which _setup_split_layout creates for us
        # This ensures perfectly consistent margins and alignment with the Register screen
        
        # --- HEADER ---
        ctk.CTkLabel(self.form_frame, text="Secure Enrollment", font=("Roboto Medium", 26), text_color="white").pack(anchor="w", pady=(0, 5))
        ctk.CTkLabel(self.form_frame, text="Scan this code to enable 2FA protection.", font=("Arial", 14), text_color="#a1a1aa").pack(anchor="w", pady=(0, 30))

        # --- QR CODE (High Tech Style) ---
        qr_container = ctk.CTkFrame(self.form_frame, fg_color="transparent")
        qr_container.pack(fill="x", pady=(0, 30))
        
        # The Border Frame (Accent Color)
        qr_border = ctk.CTkFrame(qr_container, fg_color=colors["accent"], width=204, height=204, corner_radius=6)
        qr_border.pack(anchor="center") # Center the QR in the form area
        qr_border.pack_propagate(False)
        
        # The White Plate
        qr_plate = ctk.CTkFrame(qr_border, fg_color="white", width=200, height=200, corner_radius=4)
        qr_plate.place(relx=0.5, rely=0.5, anchor="center")
        
        # Generate QR
        totp = pyotp.TOTP(mfa_secret)
        uri = totp.provisioning_uri(name="Secuta", issuer_name="Secura Vault")
        
        qr = qrcode.QRCode(box_size=15, border=0)
        qr.add_data(uri)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white").get_image()
        img_resized = img.resize((180, 180))
        
        qr_img = ctk.CTkImage(light_image=img_resized, dark_image=img_resized, size=(180, 180))
        ctk.CTkLabel(qr_plate, image=qr_img, text="").place(relx=0.5, rely=0.5, anchor="center")

        # --- MANUAL KEY (Professional Block) ---
        key_frame = ctk.CTkFrame(self.form_frame, fg_color="#09090b", border_width=1, border_color="#27272a", corner_radius=6)
        key_frame.pack(fill="x", pady=(0, 20))
        
        readable_secret = "  ".join([mfa_secret[i:i+4] for i in range(0, len(mfa_secret), 4)])
        
        ctk.CTkLabel(key_frame, text="MANUAL KEY:", font=("Arial", 10, "bold"), text_color="gray").pack(side="left", padx=15, pady=12)
        ctk.CTkLabel(key_frame, text=readable_secret, font=("Roboto Mono", 12, "bold"), text_color="white").pack(side="right", padx=15, pady=12)

        # --- VERIFICATION INPUT (Standardized) ---
        # Using the same styling as your password fields
        ctk.CTkLabel(self.form_frame, text="VERIFICATION CODE", font=("Arial", 10, "bold"), text_color=colors["text_sub"]).pack(anchor="w", pady=(0, 5))
        
        self.verify_entry = ctk.CTkEntry(self.form_frame, placeholder_text="000 000", 
                                       height=50, font=("Roboto Mono", 16), 
                                       fg_color=colors["input_bg"], border_color=colors["border"], border_width=1)
        self.verify_entry.pack(fill="x")

        # Error Status
        self.mfa_status = ctk.CTkLabel(self.form_frame, text="", text_color=colors["danger"], font=("Arial", 12))
        self.mfa_status.pack(pady=(10, 0), anchor="w")

        # --- ACTION BUTTON ---
        btn = ctk.CTkButton(self.form_frame, text="COMPLETE SETUP", height=55, corner_radius=8,
                           fg_color=colors["success"], hover_color="#059669",
                           font=("Roboto Medium", 14), 
                           command=lambda: self._finalize_mfa(password, mfa_secret, totp))
        btn.pack(fill="x", pady=30)
     
    def _finalize_mfa(self, password, secret, totp_obj):
        """Helper to keep the UI code clean."""
        code = self.verify_entry.get().replace(" ", "").strip()
        
        if len(code) != 6 or not code.isdigit():
             self.mfa_status.configure(text="Please enter the 6-digit numeric code.")
             return

        if totp_obj.verify(code, valid_window=1):
            self.perform_registration(password, self.generated_recovery_key, secret)
        else:
            self.mfa_status.configure(text="❌ Invalid code. Please wait for a new one and try again.")
            self.verify_entry.delete(0, 'end')
            self.verify_entry.configure(border_color="red")
            
    def load_tab_passwords(self):
        """Loads the password list tab."""
        if not self.master_key: return

        # Clear Content
        for widget in self.content_area.winfo_children():
            widget.destroy()

        colors = self.get_theme()
        
        # Header
        top_bar = ctk.CTkFrame(self.content_area, fg_color="transparent")
        top_bar.pack(fill="x", padx=40, pady=30)
        
        ctk.CTkLabel(top_bar, text="Secure Assets", font=("Roboto Medium", 24), text_color=colors["text_main"]).pack(anchor="w")
        ctk.CTkLabel(top_bar, text="Manage your encrypted credentials.", font=("Arial", 12), text_color=colors["text_sub"]).pack(anchor="w")

        # Search Bar
        search_frame = ctk.CTkFrame(self.content_area, fg_color="transparent")
        search_frame.pack(fill="x", padx=40, pady=(0, 20))
        
        self.search_entry = ctk.CTkEntry(search_frame, placeholder_text="Search assets...", width=300, 
                                       height=40, fg_color=colors["input_bg"], border_color=colors["border"])
        self.search_entry.pack(side="left")
        
        # Add Button
        ctk.CTkButton(search_frame, text="+ New Asset", width=120, height=40, 
                     fg_color=colors["accent"], hover_color=colors["accent_hover"],
                     command=self.show_add_password).pack(side="right")

        # Scrollable List
        self.pass_scroll = ctk.CTkScrollableFrame(self.content_area, fg_color="transparent")
        self.pass_scroll.pack(fill="both", expand=True, padx=30)

        # Load Data
        self._refresh_password_list()
        
        # Bind Search
        self.search_entry.bind("<KeyRelease>", lambda e: self._refresh_password_list(self.search_entry.get()))

    def _refresh_password_list(self, query=""):
        """Helper to fetch and render passwords."""
        # Clear list
        for widget in self.pass_scroll.winfo_children():
            widget.destroy()

        try:
            with sqlite3.connect("vault.db", timeout=5.0) as conn:
                cursor = conn.cursor()
                sql = "SELECT id, site, username FROM secrets"
                params = ()
                
                if query:
                    sql += " WHERE site LIKE ? OR username LIKE ?"
                    params = (f"%{query}%", f"%{query}%")
                
                cursor.execute(sql, params)
                rows = cursor.fetchall()

            if not rows:
                ctk.CTkLabel(self.pass_scroll, text="No assets found.", text_color="gray").pack(pady=20)
                return

            for pid, site, user in rows:
                self._create_password_row(self.pass_scroll, pid, site, user)

        except Exception as e:
            print(f"List error: {e}")
    
    def perform_registration(self, password, recovery_key, mfa_secret):
        """
        FINAL STEP: Derives keys, saves config, and boots the vault.
        """
        try:
            # 1. Generate Salts
            salt = secrets.token_bytes(32)
            hwid = SecurityCore.get_stable_hardware_id()
            
            # 2. Derive the PRIMARY Key (Hardware Bound)
            master_key = SecurityCore.derive_key(password, salt, hwid)
            
            # 3. Hash Checks
            recovery_hash = hashlib.sha256(recovery_key.encode()).hexdigest()
            verify_hash = hashlib.pbkdf2_hmac('sha256', master_key, b'verification', 100000).hex()
            
            # 4. Save Configuration (NOW INCLUDES MFA)
            config = {
                "master_salt": salt.hex(),
                "verification_hash": verify_hash,
                "recovery_hash_check": recovery_hash,
                "use_totp": True,
                "totp_secret": mfa_secret,  # <--- Saved here
                "version": "2.1",
                "security_level": "industrial"
            }
            
            with open("vault.config", "w") as f:
                json.dump(config, f, indent=2)
                
            init_database()
            
            # Cleanup Memory
            del master_key
            del password
            
            # Launch Login Screen
            self.show_login_screen()
            self.show_toast("✅ System Initialized Successfully", "green")
            
        except Exception as e:
            print(f"CRITICAL ERROR: {e}")
            # In a real app, show a popup here   
        
    
    def show_totp_qr(self, totp_secret, password):
        """Display TOTP QR code."""
        self.clear_window()
        
        header = ctk.CTkLabel(self, text="📱 Scan QR Code", 
                             font=ctk.CTkFont(size=24, weight="bold"))
        header.pack(pady=20)
        
        frame = ctk.CTkFrame(self, width=500, height=500)
        frame.pack(pady=20)
        frame.pack_propagate(False)
        
        # Generate QR code
        totp = pyotp.TOTP(totp_secret)
        uri = totp.provisioning_uri(name="FortressVault", issuer_name="Fortress")
        
        qr = qrcode.QRCode(box_size=10, border=2)
        qr.add_data(uri)
        qr.make(fit=True)
        qr_img = qr.make_image(fill_color="black", back_color="white")
        
        # Convert to PhotoImage
        qr_img = qr_img.resize((300, 300))
        photo = ImageTk.PhotoImage(qr_img)
        
        qr_label = ctk.CTkLabel(frame, image=photo, text="")
        qr_label.image = photo  # Keep reference
        qr_label.pack(pady=20)
        
        ctk.CTkLabel(frame, text="Scan with Google Authenticator or Authy",
                    font=ctk.CTkFont(size=12)).pack(pady=5)
        
        ctk.CTkLabel(frame, text=f"Manual Code: {totp_secret}",
                    font=ctk.CTkFont(size=10)).pack(pady=5)
        
        def continue_setup():
            config = {
                "use_totp": True,
                "use_biometrics": False,
                "totp_secret": totp_secret
            }
            self.finalize_setup(config, password)
        
        ctk.CTkButton(frame, text="Continue", command=continue_setup,
                     height=40).pack(pady=20)
    
    def finalize_setup(self, config, password):
        """Finalize vault creation."""
        master_salt = secrets.token_bytes(32)
        hwid = SecurityCore.get_stable_hardware_id()
        master_key =  SecurityCore.derive_key(password, master_salt, hwid)
        verification_hash = hashlib.pbkdf2_hmac('sha256', master_key, b'verification', 100000)
        
        config_data = {
            "use_totp": config["use_totp"],
            "use_biometrics": config.get("use_biometrics", False),
            "totp_secret": config.get("totp_secret", ""),
            "master_salt": master_salt.hex(),
            "verification_hash": verification_hash.hex(),
            "version": "2.0"
        }
        
        with open("vault.config", "w") as f:
            json.dump(config_data, f, indent=2)
        
        init_database()
        
        secure_zero_memory(password)
        secure_zero_memory(master_key)
        
        self.show_success_screen()
    
    def show_success_screen(self):
        """Show setup success."""
        self.clear_window()
        
        frame = ctk.CTkFrame(self, width=600, height=400)
        frame.pack(expand=True)
        frame.pack_propagate(False)
        
        ctk.CTkLabel(frame, text="✅ Vault Created Successfully!", 
                    font=ctk.CTkFont(size=24, weight="bold"),
                    text_color="green").pack(pady=40)
        
        ctk.CTkLabel(frame, text="Your passwords are now protected with:",
                    font=ctk.CTkFont(size=14)).pack(pady=10)
        
        features = [
            "🔐 AES-256-GCM Military-Grade Encryption",
            "🔗 Hardware-Bound Keys (PC-Locked)",
            "🛡️ Argon2id Anti-Brute-Force Protection",
            "🧹 Anti-Forensic Memory Wiping"
        ]
        
        for feature in features:
            ctk.CTkLabel(frame, text=feature, font=ctk.CTkFont(size=12)).pack(pady=5)
        
        ctk.CTkButton(frame, text="Login to Vault", 
                     command=self.show_login_screen,
                     height=40, font=ctk.CTkFont(size=14, weight="bold")).pack(pady=30)
       
    def show_recovery_dialog(self):
        self.show_info("Recovery System:\n\nIf you have your Recovery Key (XXXX-...), \nthis feature will be enabled in the next update step.")
     
   # ==========================================
    # ⚙️ TAB 4: SETTINGS & CONFIGURATION
    # ==========================================
    def show_settings(self):
        # 1. Clear Content
        for widget in self.content_area.winfo_children():
            widget.destroy()

        colors = self.get_theme()
        
        # Header
        top_bar = ctk.CTkFrame(self.content_area, fg_color="transparent")
        top_bar.pack(fill="x", padx=40, pady=30)
        ctk.CTkLabel(top_bar, text="System Configuration", font=("Roboto Medium", 24), text_color=colors["text_main"]).pack(anchor="w")
        ctk.CTkLabel(top_bar, text="Manage encryption keys, imports, and security protocols.", font=("Arial", 12), text_color=colors["text_sub"]).pack(anchor="w")

        # Container
        scroll = ctk.CTkScrollableFrame(self.content_area, fg_color="transparent")
        scroll.pack(fill="both", expand=True, padx=20)

        # 1. ENCRYPTION INFO CARD
        self._create_setting_card(scroll, "🔒 Encryption Standards", [
            ("Algorithm", "AES-256-GCM (Galois/Counter Mode)"),
            ("Key Derivation", "Argon2id (Memory-Hardened)"),
            ("Hardware Binding", "Active (Motherboard + CPU UUID)"),
            ("2FA Status", "Time-Based OTP (Google Authenticator)")
        ])

        # 2. DATA MANAGEMENT
        data_card = ctk.CTkFrame(scroll, fg_color=colors["bg_panel"])
        data_card.pack(fill="x", padx=20, pady=10)
        
        ctk.CTkLabel(data_card, text="💾 Data Management", font=("Roboto Medium", 14), text_color="white").pack(anchor="w", padx=20, pady=15)
        
        # Import Button Row
        row = ctk.CTkFrame(data_card, fg_color="transparent")
        row.pack(fill="x", padx=20, pady=(0, 20))
        
        ctk.CTkLabel(row, text="Import Credentials", font=("Arial", 12, "bold"), text_color="gray").pack(side="left")
        ctk.CTkLabel(row, text="Load from CSV/JSON backup", font=("Arial", 12), text_color=colors["text_sub"]).pack(side="left", padx=10)
        
        ctk.CTkButton(row, text="📂 Load Data File", width=120, height=35, 
                      fg_color=colors["input_bg"], hover_color=colors["accent"],
                      command=self.import_data_dialog).pack(side="right")

        # 3. APPLICATION INFO
        self._create_setting_card(scroll, "ℹ️ Application Info", [
            ("Version", "2.2.0-DATA-MOD"),
            ("Database Path", os.path.abspath("vault.db")),
            ("Config Path", os.path.abspath("vault.config"))
        ])

        # 4. DANGER ZONE
        danger_frame = ctk.CTkFrame(scroll, fg_color="#181111", border_width=1, border_color=colors["danger"])
        danger_frame.pack(fill="x", padx=20, pady=20)
        ctk.CTkLabel(danger_frame, text="☢️ DANGER ZONE", font=("Roboto Medium", 14), text_color=colors["danger"]).pack(anchor="w", padx=20, pady=15)
        ctk.CTkButton(danger_frame, text="INITIATE SELF-DESTRUCT", fg_color="#b91c1c", hover_color="#991b1b", 
                      height=45, command=self.initiate_self_destruct).pack(anchor="w", padx=20, pady=20)
    
    
    def import_data_dialog(self):
        """Opens a file dialog to import CSV or JSON data securely."""
        from tkinter import filedialog
        import csv
        
        file_path = filedialog.askopenfilename(
            title="Select Backup File",
            filetypes=[("Data Files", "*.csv *.json"), ("All Files", "*.*")]
        )
        
        if not file_path:
            return

        try:
            imported_count = 0
            
            if file_path.endswith('.csv'):
                with open(file_path, 'r', newline='', encoding='utf-8') as f:
                    reader = csv.DictReader(f)
                    for row in reader:
                        site = row.get('site') or row.get('url') or row.get('name')
                        user = row.get('username') or row.get('user') or row.get('login')
                        pwd  = row.get('password') or row.get('pass') or row.get('key')
                        
                        if site and pwd:
                            # Pass to secure storage helper
                            self._encrypt_and_store(site, user or "", pwd)
                            imported_count += 1
                            
            elif file_path.endswith('.json'):
                with open(file_path, 'r', encoding='utf-8') as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        for item in data:
                            site = item.get('site') or item.get('url') or item.get('name')
                            user = item.get('username') or item.get('user')
                            pwd  = item.get('password') or item.get('pass')
                            
                            if site and pwd:
                                self._encrypt_and_store(site, user or "", pwd)
                                imported_count += 1

            self.show_toast(f"✅ Successfully Imported {imported_count} Entries", "green")
            self._switch_tab(self.active_tab)
                
        except Exception as e:
            self.show_error(f"Import Failed: {str(e)}")
    
    def _encrypt_and_store(self, site, username, password):
        """Helper to encrypt and save a single entry using SecurityCore logic."""
        try:
            # 1. Use updated SecurityCore (returns 2 values)
            nonce, ciphertext_with_tag = SecurityCore.encrypt_secret(self.master_key, password)
            
            # 2. Store in DB (clearing old hmac column for native GCM)
            with sqlite3.connect("vault.db", timeout=5.0) as conn:
                cursor = conn.cursor()
                cursor.execute("""
                    INSERT INTO secrets (site, username, nonce, ciphertext, hmac) 
                    VALUES (?, ?, ?, ?, ?)
                """, (site, username, sqlite3.Binary(nonce), 
                    sqlite3.Binary(ciphertext_with_tag), sqlite3.Binary(b"")))
                conn.commit()
                
            # 3. Security: Wipe the password string from RAM
            secure_zero_memory(password)
        except Exception as e:
            print(f"Failed to import {site}: {e}")
    
    def initiate_self_destruct(self):
        """
        A high-security dialog requiring manual confirmation to wipe data.
        """
        colors = self.get_theme()
        
        # Dialog Window
        dialog = ctk.CTkToplevel(self)
        dialog.title("CRITICAL WARNING")
        dialog.geometry("450x350")
        dialog.transient(self)
        dialog.grab_set()
        
        bg = ctk.CTkFrame(dialog, fg_color="#181111") # Dark Red-ish bg
        bg.pack(fill="both", expand=True)
        
        ctk.CTkLabel(bg, text="⚠️", font=("Arial", 50)).pack(pady=(30,10))
        ctk.CTkLabel(bg, text="PERMANENT DATA WIPE", font=("Impact", 20), text_color=colors["danger"]).pack()
        
        ctk.CTkLabel(bg, text="You are about to destroy the entire vault.\nAll passwords will be cryptographically erased.\nRecovery will be impossible.", 
                    text_color="#faa", font=("Arial", 12), justify="center").pack(pady=20)
        
        ctk.CTkLabel(bg, text="Type 'DELETE' to confirm:", font=("Arial", 10, "bold"), text_color="white").pack()
        
        entry = ctk.CTkEntry(bg, height=40, justify="center", border_color=colors["danger"], fg_color="#2a0a0a")
        entry.pack(pady=10)
        entry.focus()
        
        status = ctk.CTkLabel(bg, text="", text_color="red")
        status.pack()

        def confirm_nuke():
            if entry.get() == "DELETE":
                self.reset_vault()
                dialog.destroy()
            else:
                status.configure(text="Incorrect confirmation phrase.")

        ctk.CTkButton(bg, text="CONFIRM WIPE", fg_color=colors["danger"], hover_color="red", 
                     command=confirm_nuke).pack(pady=20)

    
            
    def _create_setting_card(self, parent, title, rows):
        """Helper to draw nice data tables."""
        colors = self.get_theme()
        card = ctk.CTkFrame(parent, fg_color=colors["bg_panel"])
        card.pack(fill="x", padx=20, pady=10)
        
        ctk.CTkLabel(card, text=title, font=("Roboto Medium", 14), text_color="white").pack(anchor="w", padx=20, pady=15)
        
        for label, value in rows:
            row = ctk.CTkFrame(card, fg_color="transparent", height=30)
            row.pack(fill="x", padx=20, pady=2)
            ctk.CTkLabel(row, text=label, font=("Arial", 11, "bold"), text_color="gray", width=150, anchor="w").pack(side="left")
            ctk.CTkLabel(row, text=value, font=("Consolas", 11), text_color=colors["text_main"]).pack(side="left")
        
        ctk.CTkLabel(card, text="", height=10).pack() # Spacer
    
    def show_toast(self, message, color="green", duration=2500):
        """
        Modern, floating 'Pill' style notification with slide-up animation.
        """
        colors = self.get_theme()
        
        # 1. SETUP WINDOW
        toast = ctk.CTkToplevel(self)
        toast.overrideredirect(True)
        toast.attributes("-topmost", True)
        toast.attributes("-alpha", 0.0)  # Start invisible
        
        # 2. DETERMINE STYLING
        if color in ["green", "success"]:
            bg_col = "#10B981"   # Emerald Green
            icon = "✓"
        elif color in ["red", "error", "danger"]:
            bg_col = "#EF4444"   # Red
            icon = "✕"
        elif color in ["orange", "warning"]:
            bg_col = "#F59E0B"   # Amber
            icon = "⚠️"
        else:
            bg_col = colors["accent"]
            icon = "ℹ"

        # 3. BUILD UI (Pill Shape)
        # Main container with rounded corners
        container = ctk.CTkFrame(toast, fg_color=bg_col, corner_radius=20)
        container.pack(fill="both", expand=True)
        
        # Inner content
        content = ctk.CTkFrame(container, fg_color="transparent")
        content.pack(padx=20, pady=12)
        
        # Icon
        ctk.CTkLabel(content, text=icon, font=("Arial", 16, "bold"), text_color="white").pack(side="left", padx=(0, 10))
        
        # Text
        ctk.CTkLabel(content, text=message, font=("Roboto Medium", 14), text_color="white").pack(side="left")

        # 4. POSITIONING LOGIC (Bottom Center)
        self.update_idletasks()
        
        # Get dimensions
        toast_width = min(len(message) * 12 + 60, 400) # Auto-width based on text
        toast_height = 50
        
        main_x = self.winfo_x()
        main_y = self.winfo_y()
        main_w = self.winfo_width()
        main_h = self.winfo_height()
        
        # Calculate center-bottom position
        pos_x = main_x + (main_w // 2) - (toast_width // 2)
        pos_y = main_y + main_h - 100 # 100px from bottom
        
        toast.geometry(f"{toast_width}x{toast_height}+{pos_x}+{pos_y}")

        # 5. ANIMATION: FADE IN + SLIDE UP
        def animate_in(alpha=0.0, y_offset=20):
            if alpha < 1.0:
                alpha += 0.1
                y_offset -= 2
                # Update position and alpha
                current_y = pos_y + y_offset
                toast.geometry(f"{toast_width}x{toast_height}+{pos_x}+{int(current_y)}")
                toast.attributes("-alpha", alpha)
                toast.after(15, lambda: animate_in(alpha, y_offset))
            else:
                # Wait, then fade out
                toast.after(duration, animate_out)

        def animate_out(alpha=1.0):
            if alpha > 0:
                alpha -= 0.1
                toast.attributes("-alpha", alpha)
                toast.after(20, lambda: animate_out(alpha))
            else:
                toast.destroy()

        # Start
        animate_in()
    
    def _fade_in_toast(self, toast, alpha=0.0):
        """Smooth fade-in animation for toast."""
        if alpha < 0.95:
            alpha += 0.1
            toast.attributes("-alpha", alpha)
            toast.after(20, lambda: self._fade_in_toast(toast, alpha))
        else:
            toast.attributes("-alpha", 0.95)

    def _close_toast(self, toast):
        """Smooth fade-out and destroy toast."""
        def fade_out(alpha=0.95):
            if alpha > 0:
                alpha -= 0.1
                try:
                    toast.attributes("-alpha", alpha)
                    toast.after(20, lambda: fade_out(alpha))
                except:
                    pass
            else:
                try:
                    if hasattr(self, '_active_toasts') and toast in self._active_toasts:
                        self._active_toasts.remove(toast)
                    toast.destroy()
                except:
                    pass
        fade_out()
    
    def view_password(self, entry_data):
        """View decrypted details in a secure popup."""
        eid, site, user, nonce, cipher, mac = entry_data
        
        try:
            # Decryption with HMAC verification
            password = decrypt_secret(self.master_key, nonce, cipher, mac)
            
            view_win = ctk.CTkToplevel(self)
            view_win.title(f"Details: {site}")
            view_win.geometry("400x400")
            view_win.attributes("-topmost", True)
            
            container = ctk.CTkFrame(view_win, fg_color="transparent")
            container.pack(fill="both", expand=True, padx=20, pady=20)

            ctk.CTkLabel(container, text=site, font=("", 18, "bold")).pack(pady=10)
            
            # Username Entry (Read Only)
            ctk.CTkLabel(container, text="Username").pack(anchor="w")
            u_entry = ctk.CTkEntry(container, height=35)
            u_entry.insert(0, user)
            u_entry.configure(state="readonly")
            u_entry.pack(fill="x", pady=(0, 15))

            # Password Entry (Togglable)
            ctk.CTkLabel(container, text="Password").pack(anchor="w")
            p_entry = ctk.CTkEntry(container, height=35, show="●")
            p_entry.insert(0, password)
            p_entry.configure(state="readonly")
            p_entry.pack(fill="x", pady=(0, 5))

            def toggle():
                p_entry.configure(show="" if show_var.get() else "●")

            show_var = ctk.BooleanVar()
            ctk.CTkCheckBox(container, text="Show Password", variable=show_var, command=toggle).pack(anchor="w")

            # Auto-Type integration
            ctk.CTkButton(container, text="⌨️ Auto-Type into App", 
                        command=lambda: self.run_autotype(user, password, view_win)).pack(fill="x", pady=20)
            
        except Exception as e:
            self.show_error(f"Integrity Error: {str(e)}")
    
   
    def toggle_appearance_mode(self):
        """Switch between Dark and Light mode."""
        if ctk.get_appearance_mode() == "Dark":
            ctk.set_appearance_mode("Light")
        else:
            ctk.set_appearance_mode("Dark")
    
    def copy_password(self, entry_data):
        """Copy password to clipboard."""
        nonce, ciphertext, mac = entry_data
        try:
            password = decrypt_secret(self.master_key, nonce, ciphertext, mac)
            self.copy_to_clipboard(password)
            secure_zero_memory(password)
        except Exception as e:
            self.show_error(f"Error: {e}")
    
    def copy_to_clipboard(self, password):
        try:
            import pyperclip
            pyperclip.copy(password)
            # REPLACE self.show_info WITH THIS:
            self.show_toast("✅ Copied to Clipboard!", "green")
            
            # Auto-clear logic remains the same...
            def clear_clipboard():
                time.sleep(30)
                pyperclip.copy("")
            threading.Thread(target=clear_clipboard, daemon=True).start()
        except:
            # Fallback
            self.show_toast("❌ Clipboard Error", "red")
            
              
    
    def delete_password(self, entry_id, site_name):
        # Create a mini popup
        confirm = ctk.CTkToplevel(self)
        confirm.title("Delete Asset")
        confirm.geometry("350x200")
        confirm.transient(self)
        confirm.grab_set()
        
        # Secure the popup against screenshots
        self.after(100, lambda: self._protect_window(confirm))
        
        colors = self.get_theme()
        bg = ctk.CTkFrame(confirm, fg_color=colors["bg_dark"])
        bg.pack(fill="both", expand=True)
        
        ctk.CTkLabel(bg, text="Delete Entry?", font=("Roboto Medium", 16), text_color="white").pack(pady=(25, 10))
        ctk.CTkLabel(bg, text=f"Are you sure you want to remove:\n{site_name}", 
                     font=("Arial", 12), text_color="gray").pack(pady=5)

        btn_frame = ctk.CTkFrame(bg, fg_color="transparent")
        btn_frame.pack(pady=25)
        
        def run_delete():
            try:
                conn = sqlite3.connect("vault.db")
                c = conn.cursor()
                c.execute("DELETE FROM secrets WHERE id = ?", (entry_id,))
                conn.commit()
                conn.close()
                confirm.destroy()
                
                # FIX: Use _switch_tab instead of load_tab_passwords
                self._switch_tab("passwords") 
                self.show_toast("🗑️ Entry Deleted", "green")
            except Exception as e:
                self.show_toast(f"Error: {e}", "red")

        ctk.CTkButton(btn_frame, text="Cancel", width=100, fg_color=colors["bg_panel"], 
                      command=confirm.destroy).pack(side="left", padx=10)
                      
        ctk.CTkButton(btn_frame, text="Delete", width=100, fg_color=colors["danger"], hover_color="red",
                      command=run_delete).pack(side="left", padx=10)   
        
    def focus_search(self):
        """Focus search entry."""
        if hasattr(self, 'search_entry'):
            self.search_entry.focus()
    
    def lock_vault(self):
        """Lock vault and cleanup."""
        secure_zero_memory(self.master_key)
        self.master_key = None
        self.logged_in = False
        emergency_cleanup()
        self.show_login_screen()
    
    def show_info(self, message):
        """Show info message."""
        info = ctk.CTkToplevel(self)
        info.title("Info")
        info.geometry("350x120")
        info.resizable(False, False)
        info.transient(self)
        
        ctk.CTkLabel(info, text=message, font=ctk.CTkFont(size=12)).pack(pady=20)
        ctk.CTkButton(info, text="OK", command=info.destroy).pack(pady=10)
        
        # Auto-close after 3 seconds
        info.after(3000, info.destroy)
    
    def show_error(self, message):
        """Show error message."""
        error = ctk.CTkToplevel(self)
        error.title("Error")
        error.geometry("350x120")
        error.resizable(False, False)
        error.transient(self)
        
        ctk.CTkLabel(error, text=message, text_color="red", 
                    font=ctk.CTkFont(size=12)).pack(pady=20)
        ctk.CTkButton(error, text="OK", command=error.destroy).pack(pady=10)
    
    def clear_window(self):
        """Clear all widgets."""
        for widget in self.winfo_children():
            widget.destroy()
    
    def on_closing(self):
        """Handle window close."""
        if self.logged_in:
            secure_zero_memory(self.master_key)
        emergency_cleanup()
        self.destroy()
        
  
    def reset_vault(self):
        """Physical cryptographic erasure of all vault data."""
        # Wipe the database file
        if os.path.exists("vault.db"):
            secure_delete_file("vault.db")
        
        # Wipe the configuration (salts/hashes)
        if os.path.exists("vault.config"):
            secure_delete_file("vault.config")
            
        print("Vault securely erased. Terminating.")
        sys.exit(0)

    
# ========================
# MAIN ENTRY POINT
# ========================
if __name__ == "__main__":
    
    # Check if the file was tampered with
   

    # Check for active debuggers/reversing tools
    if not anti_debug_check():
        emergency_cleanup()
        sys.exit(1)

    # --- STEP 3: APPLICATION LAUNCH ---
    try:
        app = FortressVault()
        app.protocol("WM_DELETE_WINDOW", app.on_closing)
        app.mainloop()
    except KeyboardInterrupt:
        emergency_cleanup()
        sys.exit(0)
    except Exception as e:
        # Avoid printing specific system errors in production for better security
        emergency_cleanup()
        sys.exit(1)