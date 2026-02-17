from dotenv import load_dotenv
load_dotenv()

from flask import Flask, render_template, request,Response
from ml.predict import predict_url
from ai_utils.gemini_explainer import generate_explanation_stream


app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")

@app.route("/stream_explanation", methods=["POST"])
def stream_explanation():
    url = request.form.get("url")
    result = predict_url(url)

    def generate():
        for chunk in generate_explanation_stream(
            url=url,
            ml_score=result["ml_score"],
            ai_score=result["ai_score"],
            final_score=result["confidence"],
            risk_level=result["risk_level"],
        ):
            yield chunk

    return Response(generate(), mimetype="text/plain")

@app.route("/check", methods=["POST"])
def check_url():
    url = request.form.get("url")
    result = predict_url(url)

    return render_template(
        "result.html",
        url=url,
        result=result
    )

if __name__ == "__main__":
    app.run()
