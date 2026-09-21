from fastapi import FastAPI, Request, Form
from fastapi.responses import HTMLResponse
from fastapi.templating import Jinja2Templates

from scanner.url_analyzer import analyze_url

app = FastAPI(title="Verivex")

templates = Jinja2Templates(directory="templates")


@app.get("/", response_class=HTMLResponse)
def home(request: Request):
    return templates.TemplateResponse(request=request, name="index.html")

@app.post("/analyze")
def analyze_url_endpoint(url: str = Form(...)):
    return analyze_url(url)
    