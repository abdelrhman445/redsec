import json
import os
from datetime import datetime

HISTORY_FILE = "scan_history.json"

class HistoryManager:
    def __init__(self):
        # إنشاء ملف السجل إذا لم يكن موجوداً
        if not os.path.exists(HISTORY_FILE):
            with open(HISTORY_FILE, "w") as f:
                json.dump({}, f)

    def load_history(self):
        try:
            with open(HISTORY_FILE, "r") as f:
                return json.load(f)
        except:
            return {}

    def save_history(self, history):
        with open(HISTORY_FILE, "w") as f:
            json.dump(history, f, indent=4)

    def compare_and_save(self, target, current_ports):
        """
        يقارن البورتات الحالية بالسجلات القديمة ويرجع تقرير بالتغييرات.
        """
        history = self.load_history()
        # تنظيف الهدف لاستخدامه كمفتاح
        target_key = target.replace("http://", "").replace("https://", "").split("/")[0]
        
        old_data = history.get(target_key, {})
        old_ports = set(old_data.get("ports", []))
        new_ports = set(current_ports)
        
        # تحليل الفرق
        newly_opened = list(new_ports - old_ports)
        closed_ports = list(old_ports - new_ports)
        
        # حفظ البيانات الجديدة
        history[target_key] = {
            "last_scan": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "ports": list(new_ports)
        }
        self.save_history(history)
        
        # كتابة تقرير الفرق
        diff_report = []
        if newly_opened:
            diff_report.append(f"🚨 **ALERT: NEW PORTS OPENED** since last scan: {newly_opened}")
        if closed_ports:
            diff_report.append(f"🔒 Ports closed since last scan: {closed_ports}")
            
        if not diff_report and old_ports:
            return "✅ No changes in open ports detected since last scan."
        elif not old_ports:
            return "🆕 First time scanning this target. Baseline saved."
            
        return "\n".join(diff_report)