from typing import Dict, Any, List, Optional
from core.llm_client import llm_client
from core.prompts import CHAT_SYSTEM_PROMPT, build_chat_user_prompt
from core.forensic_chat_engine import forensic_chat_engine

class InvestigationChatAssistant:
    """
    AI Feature 7: Interactive Investigation Assistant.
    Provides context-grounded conversational interrogation of forensic email evidence.
    Answers analyst queries using the specific evidence from the current case.
    """

    def __init__(self):
        self.client = llm_client

    def chat(
        self,
        report_id: str,
        user_query: str,
        analysis_record: Dict[str, Any],
        chat_history: Optional[List[Dict[str, str]]] = None
    ) -> Dict[str, Any]:
        is_hinglish = forensic_chat_engine.is_hinglish_query(user_query)

        user_prompt = build_chat_user_prompt(
            user_query=user_query,
            analysis_record=analysis_record,
            chat_history=chat_history
        )

        response_text, telemetry = self.client.generate(
            system_prompt=CHAT_SYSTEM_PROMPT,
            user_prompt=user_prompt,
            expect_json=False
        )

        # Check if local dynamic forensic engine should generate or override
        is_fallback = telemetry.get("fallback_triggered", False)
        is_generic = "Based on forensic evidence, this email was evaluated" in str(response_text)
        is_offline_provider = telemetry.get("provider_used") == "MailGuardian Local Forensic AI Engine"

        if is_fallback or is_generic or is_hinglish or is_offline_provider or not response_text:
            local_reply, local_suggested = forensic_chat_engine.generate_response(
                query=user_query,
                record=analysis_record,
                chat_history=chat_history
            )
            telemetry.update({
                "provider_used": "MailGuardian Local Forensic AI Engine",
                "model_used": "Context-Grounded Cyber Reasoning Engine",
                "success": True
            })
            return {
                "report_id": report_id,
                "reply": local_reply,
                "suggested_questions": local_suggested[:3],
                "telemetry": telemetry
            }

        # Parse suggested questions if present
        suggested_questions = []
        clean_reply = response_text
        if "[SUGGESTED_QUESTIONS]" in response_text:
            parts = response_text.split("[SUGGESTED_QUESTIONS]")
            clean_reply = parts[0].strip()
            raw_q_block = parts[1].strip()
            for line in raw_q_block.splitlines():
                line = line.strip().lstrip("-*•0123456789. ")
                if line and len(line) > 5 and line.endswith("?"):
                    suggested_questions.append(line)

        # Default suggested questions if none extracted
        if not suggested_questions:
            suggested_questions = [
                "What specific domain authentication checks failed?",
                "What immediate containment actions should I take?",
                "Has this origin IP been involved in past security incidents?"
            ]

        return {
            "report_id": report_id,
            "reply": clean_reply,
            "suggested_questions": suggested_questions[:3],
            "telemetry": telemetry
        }

investigation_chat_assistant = InvestigationChatAssistant()
