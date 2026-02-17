import os
from dotenv import load_dotenv
from langchain_groq import ChatGroq

# 🔥 الحل هنا فقط
os.environ["OPENAI_API_KEY"] = "sk-no-openai"
os.environ["OPENAI_BASE_URL"] = "http://127.0.0.1:9999"

load_dotenv()

def get_llm():
    api_key = os.getenv("GROQ_API_KEY")

    if not api_key:
        raise ValueError("❌ GROQ_API_KEY is not set in .env file")

    return ChatGroq(
        api_key=api_key,
        model="llama-3.1-8b-instant",
        temperature=0.5,
        max_retries=3,
        request_timeout=60
    )
