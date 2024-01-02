from main import app

def create_app():
    app.config["DEBUG"] = True  
    return app