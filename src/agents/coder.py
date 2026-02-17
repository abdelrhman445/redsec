from crewai import Agent
from src.brain import get_llm
# 🔥 تصحيح الاستيراد وإضافة SASTTool
from src.tools.file_tools import CodeReaderTool, SASTTool
import yaml
import os


class CoderAgent:

    def __init__(self, llm=None):
        self.llm = llm if llm else get_llm()

        base_path = os.path.dirname(os.path.dirname(os.path.dirname(__file__)))
        config_path = os.path.join(base_path, "config", "agents.yaml")

        with open(config_path, "r", encoding="utf-8") as f:
            self.config = yaml.safe_load(f)

    # 🔥 تم تسمية الدالة coder_agent لتتوافق مع ملف telegram_bot.py
    def coder_agent(self):

        cfg = self.config["code_auditor"]

        return Agent(
            role=cfg["role"],
            goal=cfg["goal"],
            backstory=cfg["backstory"],

            # 🔥 إضافة الأدوات: القراءة + الفحص الأمني (SAST)
            tools=[
                CodeReaderTool(), 
                SASTTool()
            ],

            llm=self.llm,
            verbose=True,
            memory=False,
            allow_delegation=False,

            # 🔥 أهم 3 إعدادات
            max_iter=5,                 
            max_execution_time=60,
            max_retry_limit=0
        )