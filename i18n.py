import json
import os

LANGUAGES = {}

def load_language(lang="es"):
    global LANGUAGES
    base_path = os.path.join(os.path.dirname(__file__), "locales", f"{lang}.json")
    with open(base_path, "r", encoding="utf-8") as f:
        LANGUAGES = json.load(f)

def t(key):
    return LANGUAGES.get(key, key)