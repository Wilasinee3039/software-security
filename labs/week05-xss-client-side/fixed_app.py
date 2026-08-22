"""Secure version — Week 5 XSS. Shows escaping, CSP, and hardened cookies."""
from flask import Flask, request, Response, render_template_string
from markupsafe import escape

app = Flask(__name__)

COMMENTS = []


def secure(resp: Response) -> Response:
    # FIX CWE-79: strict Content-Security-Policy blocks inline/injected script execution.
    resp.headers["Content-Security-Policy"] = "default-src 'self'; script-src 'self'; object-src 'none'"
    resp.headers["X-Content-Type-Options"] = "nosniff"
    return resp


@app.route("/hello")
def hello():
    name = request.args.get("name", "world")
    # FIX CWE-79: contextual output encoding — escape() neutralizes <, >, &, etc.
    html = "<h1>Hello, " + str(escape(name)) + "!</h1>"
    return secure(Response(html, mimetype="text/html"))


@app.route("/comments", methods=["GET", "POST"])
def comments():
    if request.method == "POST":
        COMMENTS.append(request.form.get("body", ""))
    # FIX CWE-79: Jinja autoescaping renders stored comments as text, not markup.
    tmpl = """<h2>Comments</h2>
    <form method=post><input name=body><input type=submit value=Post></form><hr>
    {% for c in comments %}<div class=comment>{{ c }}</div>{% endfor %}"""
    page = render_template_string(tmpl, comments=COMMENTS)
    return secure(Response(page, mimetype="text/html"))


@app.route("/")
def index():
    resp = Response("<a href=/hello?name=you>hello</a> | <a href=/comments>comments</a>",
                    mimetype="text/html")
    # FIX: HttpOnly stops JS from reading the cookie; SameSite curbs cross-site send; Secure for HTTPS.
    resp.set_cookie("session", "abc123", httponly=True, samesite="Strict", secure=True)
    return secure(resp)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=False)
