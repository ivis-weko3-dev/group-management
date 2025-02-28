from .api import blueprint

class GroupManagementApp(object):
    def __init__(self, app=None):
        if app:
            self.init_app(app)

    def init_app(self, app):
        app.register_blueprint(blueprint)