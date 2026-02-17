import os
from dotenv import load_dotenv
import google.generativeai as genai

# Load .env file
load_dotenv()

api_key = os.getenv("GEMINI_API_KEY")

if not api_key:
    raise ValueError("GEMINI_API_KEY not found in environment.")

genai.configure(api_key=api_key)

model = genai.GenerativeModel("gemini-2.5-flash")


def generate_explanation(url, ml_score, ai_score, final_score, risk_level):

    prompt = f"""
    You are a cybersecurity analyst.

    URL: {url}
    ML Structural Score: {ml_score:.2f}%
    Content Intent Score: {ai_score:.2f}%
    Final Hybrid Risk Score: {final_score:.2f}%
    Risk Level: {risk_level}

    Explain clearly:
    - Why this URL is risky or safe
    - What indicators were detected
    - What a normal user should do

    Keep it under 120 words.
    """

    try:
        response = model.generate_content(prompt)
        return response.text.strip()

    except Exception as e:
        print("Gemini Error:", e)
        return "AI explanation temporarily unavailable."


def generate_explanation_stream(url, ml_score, ai_score, final_score, risk_level):

    prompt = f"""
     You are a cybersecurity analyst.

    URL: {url}
    ML Structural Score: {ml_score:.2f}%
    Content Intent Score: {ai_score:.2f}%
    Final Hybrid Risk Score: {final_score:.2f}%
    Risk Level: {risk_level}

    Explain clearly:
    - Why this URL is risky or safe
    - What indicators were detected
    - What a normal user should do

    Keep it under 120 words.
    """

    response = model.generate_content(
        prompt,
        stream=True
    )

    for chunk in response:
        if chunk.text:
            yield chunk.text
