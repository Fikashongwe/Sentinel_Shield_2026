import os
import subprocess
import threading
from PIL import Image, ImageDraw
import pystray

class SentinelTray:
    def __init__(self, base_dir: str, on_exit_callback):
        self.base_dir = base_dir
        self.on_exit_callback = on_exit_callback
        self.status_text = "Status: Active Protection"
        self.icon = pystray.Icon(
            "SentinelShield",
            self._create_shield_image("#16a34a"),
            "SentinelShield v1.1 - Active",
            menu=pystray.Menu(
                pystray.MenuItem(lambda text: self.status_text, None, enabled=False),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("Open Agent Folder", self._open_folder),
                pystray.MenuItem("Restore Network Adapter", self._restore_network),
                pystray.Menu.SEPARATOR,
                pystray.MenuItem("Exit SentinelShield", self._exit_app),
            )
        )

    def _create_shield_image(self, fill_color: str) -> Image.Image:
        img = Image.new("RGBA", (64, 64), (0, 0, 0, 0))
        draw = ImageDraw.Draw(img)
        shield_pts = [(32, 4), (56, 14), (52, 38), (32, 60), (12, 38), (8, 14)]
        draw.polygon(shield_pts, fill=fill_color, outline="#ffffff")
        return img

    def set_lockdown_state(self):
        self.status_text = "Status: LOCKDOWN TRIGGERED"
        self.icon.icon = self._create_shield_image("#dc2626")
        self.icon.title = "SentinelShield v1.1 - LOCKDOWN ACTIVE"

    def _open_folder(self, icon, item):
        os.startfile(self.base_dir)

    def _restore_network(self, icon, item):
        bat_path = os.path.join(self.base_dir, "Restore_Network.bat")
        if os.path.exists(bat_path):
            subprocess.Popen(["cmd.exe", "/c", bat_path], shell=False)

    def _exit_app(self, icon, item):
        self.icon.stop()
        self.on_exit_callback()

    def run_detached(self):
        t = threading.Thread(target=self.icon.run, daemon=True)
        t.start()
        return t
