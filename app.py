from flask import Flask, render_template, request
from ml.predict import predict_url

app = Flask(__name__)

@app.route("/")
def home():
    return render_template("index.html")

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
