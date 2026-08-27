"""Windows desktop launcher for the self-contained ASTG installation."""
from __future__ import annotations

import ctypes
import logging
import os
import subprocess
import sys
import threading
import time
import urllib.request
import webbrowser
from pathlib import Path
from tkinter import Button, Label, Tk, messagebox
from ctypes import wintypes


APP_NAME = "AI Software Trust Gateway"
WEB_URL = "http://127.0.0.1:3000"
API_READY_URL = "http://127.0.0.1:8000/api/v1/health/ready"


def app_root() -> Path:
    return Path(sys.executable).resolve().parent if getattr(sys, "frozen", False) else Path(__file__).resolve().parents[1]


def data_root() -> Path:
    configured = os.environ.get("ASTG_DATA_DIR")
    if configured:
        return Path(configured).expanduser().resolve()
    local_app_data = os.environ.get("LOCALAPPDATA") or os.environ.get("APPDATA")
    return Path(local_app_data or Path.home()) / APP_NAME


def acquire_single_instance() -> bool:
    if os.name != "nt":
        return True
    ctypes.windll.kernel32.CreateMutexW(None, False, "Local\\ASTGDesktopLauncher-10B679A7")
    return ctypes.windll.kernel32.GetLastError() != 183


class _IoCounters(ctypes.Structure):
    _fields_ = [(name, ctypes.c_ulonglong) for name in (
        "ReadOperationCount", "WriteOperationCount", "OtherOperationCount",
        "ReadTransferCount", "WriteTransferCount", "OtherTransferCount",
    )]


class _BasicLimitInformation(ctypes.Structure):
    _fields_ = [
        ("PerProcessUserTimeLimit", ctypes.c_longlong),
        ("PerJobUserTimeLimit", ctypes.c_longlong),
        ("LimitFlags", wintypes.DWORD),
        ("MinimumWorkingSetSize", ctypes.c_size_t),
        ("MaximumWorkingSetSize", ctypes.c_size_t),
        ("ActiveProcessLimit", wintypes.DWORD),
        ("Affinity", ctypes.c_size_t),
        ("PriorityClass", wintypes.DWORD),
        ("SchedulingClass", wintypes.DWORD),
    ]


class _ExtendedLimitInformation(ctypes.Structure):
    _fields_ = [
        ("BasicLimitInformation", _BasicLimitInformation),
        ("IoInfo", _IoCounters),
        ("ProcessMemoryLimit", ctypes.c_size_t),
        ("JobMemoryLimit", ctypes.c_size_t),
        ("PeakProcessMemoryUsed", ctypes.c_size_t),
        ("PeakJobMemoryUsed", ctypes.c_size_t),
    ]


def assign_kill_on_close_job(process: subprocess.Popen):
    """Ensure the bundled Web child exits even if the launcher is force-killed."""
    if os.name != "nt":
        return None
    kernel32 = ctypes.windll.kernel32
    kernel32.CreateJobObjectW.restype = wintypes.HANDLE
    kernel32.SetInformationJobObject.argtypes = [wintypes.HANDLE, ctypes.c_int, ctypes.c_void_p, wintypes.DWORD]
    kernel32.AssignProcessToJobObject.argtypes = [wintypes.HANDLE, wintypes.HANDLE]
    kernel32.CloseHandle.argtypes = [wintypes.HANDLE]
    job = kernel32.CreateJobObjectW(None, None)
    if not job:
        raise ctypes.WinError()
    info = _ExtendedLimitInformation()
    info.BasicLimitInformation.LimitFlags = 0x00002000  # JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
    if not kernel32.SetInformationJobObject(job, 9, ctypes.byref(info), ctypes.sizeof(info)):
        kernel32.CloseHandle(job)
        raise ctypes.WinError()
    if not kernel32.AssignProcessToJobObject(job, wintypes.HANDLE(process._handle)):
        kernel32.CloseHandle(job)
        raise ctypes.WinError()
    return job


class DesktopLauncher:
    def __init__(self) -> None:
        self.root = Tk()
        self.root.title(APP_NAME)
        self.root.geometry("460x250")
        self.root.resizable(False, False)
        self.root.protocol("WM_DELETE_WINDOW", self.stop)
        self.frontend_process: subprocess.Popen | None = None
        self.api_server = None
        self.api_thread: threading.Thread | None = None
        self.frontend_job = None
        self.status = Label(self.root, text="正在启动本地安全服务…", font=("Microsoft YaHei UI", 11))
        self.status.pack(pady=(32, 20))
        Button(self.root, text="打开管理界面", width=24, command=self.open_web).pack(pady=5)
        Button(self.root, text="打开数据和报告目录", width=24, command=self.open_data).pack(pady=5)
        Button(self.root, text="退出本地服务", width=24, command=self.stop).pack(pady=5)

    def start(self) -> None:
        data_dir = data_root()
        data_dir.mkdir(parents=True, exist_ok=True)
        os.environ.setdefault("ASTG_DATA_DIR", str(data_dir))
        os.environ.setdefault("ASTG_HOST", "127.0.0.1")
        os.environ.setdefault("ASTG_PORT", "8000")
        os.environ.setdefault("ASTG_RELOAD", "false")
        logging.basicConfig(
            filename=str(data_dir / "launcher.log"),
            level=logging.INFO,
            encoding="utf-8",
            format="%(asctime)s %(levelname)s %(message)s",
        )
        try:
            self._start_api()
            self._start_frontend()
            threading.Thread(target=self._wait_until_ready, daemon=True).start()
        except Exception as exc:
            logging.exception("ASTG startup failed")
            messagebox.showerror(APP_NAME, f"启动失败：{exc}\n\n详细信息已写入：{data_dir / 'launcher.log'}")
            self.stop()
            return
        self.root.mainloop()

    def _start_api(self) -> None:
        import uvicorn
        from backend.app.main import app

        config = uvicorn.Config(app, host="127.0.0.1", port=8000, log_level="info", access_log=False)
        self.api_server = uvicorn.Server(config)
        self.api_thread = threading.Thread(target=self.api_server.run, name="astg-api", daemon=True)
        self.api_thread.start()

    def _start_frontend(self) -> None:
        root_dir = app_root()
        node_exe = root_dir / "runtime" / "node.exe"
        server_js = root_dir / "frontend" / "server.js"
        if not node_exe.exists() or not server_js.exists():
            raise FileNotFoundError("安装文件不完整：缺少 Web 运行组件")
        env = os.environ.copy()
        env.update({"NODE_ENV": "production", "PORT": "3000", "HOSTNAME": "127.0.0.1"})
        creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
        self.frontend_process = subprocess.Popen(
            [str(node_exe), str(server_js)],
            cwd=str(server_js.parent),
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            creationflags=creation_flags,
        )
        self.frontend_job = assign_kill_on_close_job(self.frontend_process)

    def _wait_until_ready(self) -> None:
        deadline = time.time() + 45
        while time.time() < deadline:
            if self.frontend_process and self.frontend_process.poll() is not None:
                self.root.after(0, lambda: self.status.config(text="Web 服务启动失败，请查看日志"))
                return
            try:
                with urllib.request.urlopen(API_READY_URL, timeout=1) as response:
                    api_ready = response.status == 200
                with urllib.request.urlopen(WEB_URL, timeout=1) as response:
                    web_ready = response.status == 200
                if api_ready and web_ready:
                    self.root.after(0, lambda: self.status.config(text="本地安全网关已就绪"))
                    self.root.after(0, self.open_web)
                    return
            except Exception:
                time.sleep(0.5)
        self.root.after(0, lambda: self.status.config(text="启动超时，请查看数据目录中的 launcher.log"))

    @staticmethod
    def open_web() -> None:
        webbrowser.open(WEB_URL)

    @staticmethod
    def open_data() -> None:
        target = data_root()
        target.mkdir(parents=True, exist_ok=True)
        os.startfile(str(target))

    def stop(self) -> None:
        if self.api_server is not None:
            self.api_server.should_exit = True
        if self.frontend_process and self.frontend_process.poll() is None:
            self.frontend_process.terminate()
            try:
                self.frontend_process.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.frontend_process.kill()
        if self.frontend_job and os.name == "nt":
            ctypes.windll.kernel32.CloseHandle(self.frontend_job)
            self.frontend_job = None
        try:
            self.root.destroy()
        except Exception:
            pass


def main() -> None:
    if not acquire_single_instance():
        webbrowser.open(WEB_URL)
        return
    DesktopLauncher().start()


if __name__ == "__main__":
    main()
