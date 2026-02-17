import chromadb
import uuid
from datetime import datetime

class MemoryCenter:
    def __init__(self):
        # إنشاء قاعدة بيانات محلية في مجلد brain_db
        self.client = chromadb.PersistentClient(path="./brain_db")
        
        # إنشاء "مجموعة" لتخزين المعلومات الأمنية
        self.collection = self.client.get_or_create_collection(
            name="security_knowledge",
            metadata={"hnsw:space": "cosine"} # طريقة البحث (التشابه)
        )

    def memorize(self, target, findings, risk):
        """
        تخزين تجربة جديدة في الذاكرة
        """
        doc_id = f"{target}_{datetime.now().strftime('%Y%m%d%H%M')}"
        
        # تخزين النص + البيانات الوصفية (Metadata)
        self.collection.add(
            documents=[findings], # محتوى التقرير
            metadatas=[{"target": target, "risk": risk, "date": str(datetime.now())}],
            ids=[doc_id]
        )
        print(f"🧠 [Memory] Stored knowledge for {target}.")

    def recall(self, target):
        """
        استرجاع المعلومات السابقة عن هدف معين
        """
        results = self.collection.query(
            query_texts=[target],
            n_results=1 # هات أقرب نتيجة واحدة
        )
        
        if results['documents'][0]:
            past_info = results['documents'][0][0]
            past_meta = results['metadatas'][0][0]
            return f"💡 I remember scanning {past_meta['target']} before on {past_meta['date']}. Risk was {past_meta['risk']}.\nPast Findings: {past_info[:200]}..."
        
        return None