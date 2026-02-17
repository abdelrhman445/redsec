#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""
RedSec All-in-One (Cyberpunk Ultimate Edition)
==============================================
- Core Logic: Full Deep Recon, Audit, Auto-Failover (Llama 3.1/3.3), Smart Reporting.
- UI: Cyberpunk Theme, ASCII Art, Loading Spinners, Boxed Logs.
- Status: Production Ready & Clean.
"""

import os
import sys
import time
import uuid
import re
import warnings
import subprocess
import json
import asyncio
import traceback
import psutil
import logging
from datetime import datetime

# ============================================================
# 🔇 Silence the Noise (Log Cleaning)
# ============================================================
def configure_clean_logging():
    # كتم صوت كل المكتبات الخارجية المزعجة
    loggers = [
        'httpx', 'httpcore', 'telegram', 'uagents', 'urllib3', 
        'chromadb', 'crewai', 'alembic', 'posthog', 'backoff'
    ]
    for l in loggers:
        logging.getLogger(l).setLevel(logging.CRITICAL) # أعلى درجة كتم
    
    # إعداد اللوجر الخاص بنا فقط
    logging.basicConfig(format='%(message)s', level=logging.ERROR)

configure_clean_logging()
warnings.filterwarnings("ignore")

# ============================================================
# 🎨 Cyberpunk UI Engine (محرك الواجهة)
# ============================================================
class UI:
    # ألوان النيون
    HEADER = "\033[95m"
    BLUE = "\033[94m"
    CYAN = "\033[96m"
    GREEN = "\033[92m"
    YELLOW = "\033[93m"
    RED = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"
    
    @staticmethod
    def banner():
        """عرض بانر البداية"""
        os.system('cls' if os.name == 'nt' else 'clear')
        print(f"{UI.RED}")
        print(r"""
    ██████╗ ███████╗██████╗ ███████╗███████╗ ██████╗
    ██╔══██╗██╔════╝██╔══██╗██╔════╝██╔════╝██╔════╝
    ██████╔╝█████╗  ██║  ██║███████╗█████╗  ██║     
    ██╔══██╗██╔══╝  ██║  ██║╚════██║██╔══╝  ██║     
    ██║  ██║███████╗██████╔╝███████║███████╗╚██████╗
    ╚═╝  ╚═╝╚══════╝╚═════╝ ╚══════╝╚══════╝ ╚═════╝
        """)
        print(f"{UI.CYAN}   >> REDSEC ULTIMATE INTELLIGENCE SYSTEM v7.0 <<{UI.ENDC}")
        print(f"{UI.BLUE}   {'='*55}{UI.ENDC}\n")

    @staticmethod
    def type_writer(text, speed=0.01, color=CYAN):
        """تأثير الكتابة"""
        sys.stdout.write(color)
        for char in text:
            sys.stdout.write(char)
            sys.stdout.flush()
            time.sleep(speed)
        sys.stdout.write(UI.ENDC + "\n")

    @staticmethod
    def spinner(text, duration=2.0):
        """مؤشر تحميل"""
        chars = "⠋⠙⠹⠸⠼⠴⠦⠧⠇⠏"
        end_time = time.time() + duration
        i = 0
        sys.stdout.write(UI.YELLOW)
        while time.time() < end_time:
            sys.stdout.write(f"\r {chars[i % len(chars)]} {text}...")
            sys.stdout.flush()
            time.sleep(0.1)
            i += 1
        sys.stdout.write(f"\r {UI.GREEN}✔ {text} Done.      {UI.ENDC}\n")

    @staticmethod
    def log(tag, message, level="INFO"):
        """لوجات ملونة ومنظمة"""
        timestamp = datetime.now().strftime("%H:%M:%S")
        
        if level == "INFO": color = UI.BLUE; icon = "ℹ️"
        elif level == "SUCCESS": color = UI.GREEN; icon = "✅"
        elif level == "WARN": color = UI.YELLOW; icon = "⚠️"
        elif level == "ERROR": color = UI.RED; icon = "💀"
        elif level == "SYSTEM": color = UI.HEADER; icon = "⚙️"
        else: color = UI.CYAN; icon = "➤"

        print(f"{UI.BOLD}[{timestamp}]{UI.ENDC} {color}[{tag.center(8)}]{UI.ENDC} {icon} {message}")

    @staticmethod
    def box_log(title, content, color=GREEN):
        """طباعة داخل صندوق"""
        lines = content.split('\n')
        max_len = max([len(line) for line in lines] + [len(title)]) + 4
        print(color)
        print(f"┌{'─'*max_len}┐")
        print(f"│ {title.center(max_len-2)} │")
        print(f"├{'─'*max_len}┤")
        for line in lines:
            print(f"│ {line.ljust(max_len-2)} │")
        print(f"└{'─'*max_len}┘{UI.ENDC}")

# ============================================================
# 🧹 Port Management
# ============================================================
def kill_port_owner(port: int):
    try:
        for proc in psutil.process_iter(["pid", "name"]):
            try:
                for conn in proc.net_connections(kind="inet"):
                    if conn.laddr and conn.laddr.port == port:
                        if "python" in proc.name().lower():
                            UI.log("CLEANUP", f"Freeing Port {port} (PID: {proc.pid})", "WARN")
                            proc.kill()
            except (psutil.NoSuchProcess, psutil.AccessDenied): continue
    except ImportError: pass

# ============================================================
# 🌍 Environment Setup
# ============================================================
def load_env():
    try:
        from dotenv import load_dotenv
        load_dotenv()
    except Exception:
        UI.log("ENV", "python-dotenv not installed.", "WARN")
    
    os.environ.setdefault("OPENAI_API_KEY", "sk-no-openai")
    os.environ.setdefault("OPENAI_BASE_URL", "http://127.0.0.1:9999")

# ============================================================
# ======================= Telegram Bot (Client) ==============
# ============================================================
def run_telegram_bot():
    """
    Client Interface. Handles User Commands & Smart Reporting.
    Contains the Embedded Client Agent.
    """
    from telegram import Update
    from telegram.ext import ApplicationBuilder, CommandHandler, ContextTypes, MessageHandler, filters
    from telegram.request import HTTPXRequest
    from uagents import Agent, Context, Model
    from uagents.setup import fund_agent_if_low
    from src.agents.coder import CoderAgent
    from crewai import Crew, Task
    from langchain_groq import ChatGroq

    TOKEN = os.getenv("TELEGRAM_TOKEN")
    GROQ_API_KEY = os.getenv("GROQ_API_KEY")

    if not TOKEN: 
        UI.log("ERROR", "No TELEGRAM_TOKEN found.", "ERROR")
        return

    # --- Models ---
    class SecurityScanRequest(Model):
        target_domain: str

    class SecurityScanResponse(Model):
        report: str
        risk_level: str
        memory_recall: str

    # --- Client Agent Setup ---
    client = Agent(
        name="redsec_client",
        seed="RedSec_Client_Ultimate_Cyberpunk_V1", 
        port=8001,
        endpoint=["http://127.0.0.1:8001/submit"],
        network="testnet"
    )
    
    UI.log("CLIENT", "Initializing Client Wallet...", "INFO")
    try:
        fund_agent_if_low(client.wallet.address())
    except: pass 

    # --- State Management ---
    scan_queue = asyncio.Queue()
    pending_responses = {}

    def get_server_address():
        try:
            with open("server_address.txt", "r") as f:
                return f.read().strip()
        except FileNotFoundError: return None

    # --- Agent Logic ---
    @client.on_interval(period=1.0)
    async def process_queue(ctx: Context):
        if not scan_queue.empty():
            target = await scan_queue.get()
            addr = get_server_address()
            if addr:
                UI.log("CLIENT", f"Sending Mission Payload -> {target}", "SUCCESS")
                await ctx.send(addr, SecurityScanRequest(target_domain=target))
            else:
                UI.log("CLIENT", "Searching for Server Uplink...", "WARN")
                await scan_queue.put(target) 

    @client.on_message(model=SecurityScanResponse)
    async def handle_resp(ctx: Context, sender: str, msg: SecurityScanResponse):
        UI.log("CLIENT", "Intelligence Package Received!", "SUCCESS")
        pending_responses['last'] = msg

    # --- Local Helpers ---
    def get_chat_model():
        # Using Llama 3.3 as primary for local audit (Very strong)
        return ChatGroq(api_key=GROQ_API_KEY, model="llama-3.3-70b-versatile", temperature=0.5)

    def execute_crew(crew):
        return crew.kickoff()

    # --- Telegram Handlers ---
    async def start(update: Update, context: ContextTypes.DEFAULT_TYPE):
        await update.message.reply_text(
            "⚡ RedSec Cyberpunk Agent\n"
            "━━━━━━━━━━━━━━━━━\n"
            "🕵️‍♂️ `/scan domain.com` -> Global Deep Recon\n"
            "💻 `Upload .py` -> Local Code Audit"
        )

    async def scan(update: Update, context: ContextTypes.DEFAULT_TYPE):
        if not context.args:
            await update.message.reply_text("❌ Usage: `/scan domain.com`")
            return

        target = context.args[0]
        status_msg = await update.message.reply_text(
            f"🚀 Target Acquired: `{target}`\n"
            f"📡 Status: Connecting to RedSec Network...\n"
            f"⏳ Est. Time: 2-5 Minutes (Deep Analysis)"
        )

        try:
            if not get_server_address():
                await status_msg.edit_text("❌ Server Agent not ready. Please wait a moment.")
                return

            if 'last' in pending_responses: del pending_responses['last']
            await scan_queue.put(target)
            
            # Timeout loop (10 minutes)
            for _ in range(300): 
                if 'last' in pending_responses:
                    resp = pending_responses['last']
                    report = resp.report
                    
                    # 🔥 SMART REPORTING 🔥
                    if len(report) > 3000:
                        filename = f"RedSec_Report_{target}.txt"
                        with open(filename, "w", encoding="utf-8") as f:
                            f.write(report)
                        
                        await status_msg.edit_text(
                            f"✅ Scan Complete: {target}\n"
                            f"⚠️ Risk Level: {resp.risk_level}\n"
                            f"🧠 Memory Recall: {resp.memory_recall[:50]}...\n"
                            f"📄 Report is comprehensive. Sending as file..."
                        )
                        await context.bot.send_document(
                            chat_id=update.effective_chat.id,
                            document=open(filename, "rb"),
                            caption=f"🔒 Classified Security Report: {target}"
                        )
                        os.remove(filename)
                    else:
                        try:
                            await status_msg.edit_text(
                                f"✅ Scan Complete: {target}\n"
                                f"⚠️ Risk: {resp.risk_level}\n\n{report}", 
                                parse_mode="Markdown"
                            )
                        except Exception:
                            await status_msg.edit_text(
                                f"✅ Scan Complete: {target}\n"
                                f"⚠️ Risk: {resp.risk_level}\n\n{report}", 
                                parse_mode=None
                            )
                    return
                await asyncio.sleep(2)
            
            await status_msg.edit_text("⚠️ Timeout: The Agent is taking longer than expected.")

        except Exception as e:
            await status_msg.edit_text(f"❌ Error: {str(e)}")

    async def handle_document(update: Update, context: ContextTypes.DEFAULT_TYPE):
        msg = await update.message.reply_text("🛡️ Analyzing Code Locally...")
        try:
            doc = update.message.document
            f = await doc.get_file()
            c = (await f.download_as_bytearray()).decode("utf-8", "ignore")
            
            llm = get_chat_model()
            coder = CoderAgent(llm).coder_agent()
            
            task = Task(
                description=f"Perform SAST on:\n{doc.file_name}\nIdentify vulns & fix them.", 
                expected_output="Audit Report.", 
                agent=coder
            )
            
            crew = Crew(agents=[coder], tasks=[task], verbose=True, max_rpm=10)
            loop = asyncio.get_running_loop()
            res = await loop.run_in_executor(None, execute_crew, crew)
            
            final_res = str(res)
            if len(final_res) > 3000:
                filename = f"Audit_{doc.file_name}.txt"
                with open(filename, "w", encoding="utf-8") as f: f.write(final_res)
                await msg.edit_text("✅ Audit complete. Sending file...")
                await context.bot.send_document(chat_id=update.effective_chat.id, document=open(filename, "rb"))
                os.remove(filename)
            else:
                await msg.edit_text(final_res)

        except Exception as e:
            await msg.edit_text(f"❌ Audit Error: {e}")

    UI.log("TELEGRAM", "Interface Active", "SUCCESS")
    async def post_init(application):
        asyncio.create_task(client.run_async())

    t_request = HTTPXRequest(connect_timeout=60, read_timeout=60)
    app = ApplicationBuilder().token(TOKEN).request(t_request).post_init(post_init).build()
    app.add_handler(CommandHandler("start", start))
    app.add_handler(CommandHandler("scan", scan))
    app.add_handler(MessageHandler(filters.Document.ALL, handle_document))
    app.run_polling()

# ============================================================
# ========================= uAgent Server (Brain) ============
# ============================================================
def run_uagent_core():
    """Server Agent with Smart Failover & Memory"""
    from uagents import Agent, Context, Model
    from uagents.setup import fund_agent_if_low
    from crewai import Crew, Task
    from langchain_groq import ChatGroq
    from src.agents.pentester import PentestAgents
    from src.utils.memory_db import MemoryCenter

    GROQ_API_KEY = os.getenv("GROQ_API_KEY")
    if not GROQ_API_KEY: raise RuntimeError("GROQ_API_KEY missing.")

    brain = MemoryCenter()
    NGROK_URL = os.getenv("NGROK_URL", "https://presumingly-nonoccidental-jacqueline.ngrok-free.dev")
    endpoint_submit = os.getenv("UAGENT_ENDPOINT", f"{NGROK_URL.rstrip('/')}/submit")

    class SecurityScanRequest(Model): target_domain: str
    class SecurityScanResponse(Model): report: str; risk_level: str; memory_recall: str
    class ThreatIntelShare(Model): target: str; vulnerabilities: list; risk_score: str

    server = Agent(
        name="redsec_server",
        seed="RedSec_Server_Ultimate_Final_V4", 
        port=8000,
        endpoint=[endpoint_submit],
        network="testnet"
    )

    try: fund_agent_if_low(server.wallet.address())
    except: pass

    UI.box_log("SERVER ONLINE", f"ID: {server.address}", UI.CYAN)
    with open("server_address.txt", "w") as f: f.write(server.address)

    # --- 🔥 AI ENGINE (Smart Failover) ---
    def run_crew_scan(target, history):
        MODELS = [
            "llama-3.1-8b-instant", 
            "llama-3.3-70b-versatile",
            "llama3-70b-8192", 
            "gemma2-9b-it"
        ]
        
        for model in MODELS:
            try:
                UI.log("AI-CORE", f"Engaging Model: {model}", "INFO")
                llm = ChatGroq(api_key=GROQ_API_KEY, model=model, temperature=0.2)
                agents = PentestAgents(llm)
                
                t1 = Task(description=f"Deep Recon: {target}. Shodan/Headers/Subdomains. Context: {history}", expected_output="Tech Data", agent=agents.scanner_agent())
                t2 = Task(description=f"Report for {target}. Mitigation/Vulns.", expected_output="Markdown Report", agent=agents.report_writer_agent(), context=[t1])
                
                crew = Crew(agents=[agents.scanner_agent(), agents.report_writer_agent()], tasks=[t1, t2], verbose=True, max_rpm=10)
                return str(crew.kickoff())
            except Exception as e:
                if "429" in str(e) or "400" in str(e):
                    UI.log("AI-FAIL", f"{model} Exhausted. Rerouting...", "WARN")
                    continue
                return f"Internal Error: {e}"
        return "❌ All Models Exhausted."

    @server.on_message(model=SecurityScanRequest)
    async def handle_scan(ctx: Context, sender: str, msg: SecurityScanRequest):
        UI.log("MISSION", f"Target Acquired: {msg.target_domain}", "WARN")
        
        history = brain.recall(msg.target_domain)
        report = run_crew_scan(msg.target_domain, history)
        
        risk = "HIGH" if "critical" in str(report).lower() else "MEDIUM"
        if "error" in str(report).lower(): risk = "ERROR"
        
        # 3. ⬇️⬇️ التصحيح: شلنا شرط (!= ctx.address) ⬇️⬇️
        # بنكتفي بالتأكد إن معانا عنوان نبعتله وبس
       # if TARGET_ADDRESS:
            #UI.log("NET-OUT", f"Forwarding Report to HQ...", "INFO")
            
            # تحويل التقرير لنص (عشان نتجنب أي مشاكل في نوع البيانات)
            #final_report = str(report)
            
           # await ctx.send(TARGET_ADDRESS, MessageForFriend(
               # text=f"🚨 New Scan Alert!\nTarget: {msg.target_domain}\nRisk: {risk}\n\nSummary: {final_report[:200]}..."
            #))

        brain.memorize(msg.target_domain, str(report), risk)
        await ctx.send(sender, SecurityScanResponse(report=str(report), risk_level=risk, memory_recall=str(history)[:100]))
        UI.log("MISSION", "Execution Complete. Data Transmitted.", "SUCCESS")

    @server.on_message(model=ThreatIntelShare)
    async def handle_intel(ctx: Context, sender: str, msg: ThreatIntelShare):
        brain.memorize(msg.target, str(msg.vulnerabilities), msg.risk_score)

# ============================================================
# 📡 الاتصال بالضابط المناوب (Duty Officer)
# ============================================================
    
    class MessageForFriend(Model):
        text: str

    # ده عنوان الوكيل التاني اللي احنا لسه جايبينه
    TARGET_ADDRESS = "agent1qf2nqq85tkwe8gpsk488nsggfjg4n2wf5g53fnj3y6mq4fmehawz7xytv24" 


#اتصال بالبوت كل 10 قواني 

   # @server.on_interval(period=10.0)
    #async def ping_friend(ctx: Context):
        # 🟢 التعديل: شيلنا شرط if ctx.address لأنه كان بيعمل Error
        # وبنبعت الرسالة علطول لأننا عارفين العنوان
       # UI.log("NET-OUT", "Contacting Duty Officer...", "INFO")
       # await ctx.send(TARGET_ADDRESS, MessageForFriend(text=f"RedSec Heartbeat: System Active."))

    @server.on_message(model=MessageForFriend)
    async def handle_friend_reply(ctx: Context, sender: str, msg: MessageForFriend):
        UI.log("NET-IN", f"Incoming Transmission: {msg.text}", "SUCCESS")

    server.run()

# ============================================================
# ========================= Supervisor =======================
# ============================================================
def run_supervisor():
    UI.banner()
    UI.type_writer(" >> INITIALIZING REDSEC SUPERVISOR...", speed=0.02)
    
    python_exec = sys.executable
    this_file = os.path.abspath(__file__)
    
    kill_port_owner(8000)
    kill_port_owner(8001)

    agent_proc = None
    tg_proc = None

    try:
        UI.spinner("Booting Server Brain")
        agent_proc = subprocess.Popen([python_exec, this_file, "--mode", "uagent"])
        time.sleep(8) 

        UI.spinner("Connecting Secure Uplink")
        tg_proc = subprocess.Popen([python_exec, this_file, "--mode", "telegram"])

        UI.box_log("SYSTEM STATUS", "ALL SYSTEMS OPERATIONAL\nLISTENING FOR COMMANDS", UI.GREEN)

        while True:
            time.sleep(20)
            if agent_proc.poll() is not None:
                UI.log("WATCHDOG", "Server Down. Rebooting...", "ERROR")
                kill_port_owner(8000)
                agent_proc = subprocess.Popen([python_exec, this_file, "--mode", "uagent"])
            
            if tg_proc.poll() is not None:
                UI.log("WATCHDOG", "Telegram Down. Rebooting...", "ERROR")
                kill_port_owner(8001)
                tg_proc = subprocess.Popen([python_exec, this_file, "--mode", "telegram"])

    except KeyboardInterrupt:
        print("\n")
        UI.log("SYSTEM", "Shutdown Sequence Initiated...", "ERROR")
        if agent_proc: agent_proc.kill()
        if tg_proc: tg_proc.kill()
        kill_port_owner(8000)
        kill_port_owner(8001)

# ============================================================
# ============================= Entry ========================
# ============================================================
def parse_mode(argv):
    mode = "supervisor"
    if "--mode" in argv:
        if len(argv) > argv.index("--mode") + 1:
            mode = argv[argv.index("--mode") + 1].strip().lower()
    return mode

if __name__ == "__main__":
    load_env()
    mode = parse_mode(sys.argv)
    
    if mode == "supervisor": run_supervisor()
    elif mode == "uagent": run_uagent_core()
    elif mode == "telegram": run_telegram_bot()
    else: sys.exit(1)