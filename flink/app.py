# app.py
from flask import Flask, render_template, request
from link import LinkAnalyzer

app = Flask(__name__)

@app.route("/", methods=["GET", "POST"])
def index():
    result = None
    if request.method == "POST":
        url = request.form["url"]
        analyzer = LinkAnalyzer(url)
        result = analyzer.analyze()
        print(result)  # Debugging line to print the result to the console
    return render_template("index.html", result=result)

if __name__ == "__main__":
    app.run(debug=True)
