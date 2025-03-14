from flask import Flask
from logging import FileHandler

from group_management.ext import GroupManagementApp

app = Flask(__name__)

file_handler = FileHandler('/var/log/group-management/uwsgi.log')
app.logger.addHandler(file_handler)
app.logger.setLevel('INFO')

GroupManagementApp(app)

if __name__ == '__main__':
    app.run()