from sql_alchemy import database
from flask import request, url_for
from requests import post

MAILGUN_DOMAIN = 'YourDomain'
MAILGUN_API_KEY = 'YourApiKey'
FROM_TITLE = 'No-Reply'
FROM_EMAIL = 'no-reply@relatory.com'

class UserModel(database.Model):
    __tablename__ = 'users'

    user_id = database.Column(database.Integer, primary_key=True)
    login = database.Column(database.String(40))
    password = database.Column(database.String(40))
    email = database.Column(database.String(80), nullable=False, unique=True)
    active = database.Column(database.Boolean, default=False)

    def __init__(self, login, password, email, active):
        self.login = login
        self.password = password
        self.email = email
        self.active = active

    def send_confirmation_email(self):
        # /confirm/{user_id}
        link = request.url_root[:-1] + url_for('userconfirm', user_id=self.user_id)
        return post('https://api.mailgun.net/v3/{}/messages'.format(MAILGUN_DOMAIN),
                    auth=('api', MAILGUN_API_KEY),
                    data={'from': '{} <{}>'.format(FROM_TITLE, FROM_EMAIL),
                          'to': self.email,
                          'subject': 'Register Confirm',
                          'text': 'Confirm your account: {}'.format(link),
                          'html': '<html><p>\
                          Confirm : <a href="{}">Confirm email</a>\
                          </p></html>'.format(link)
                          }
                    )

    def json(self):
        return {
            'user_id': self.user_id,
            'login': self.login
            }

    @classmethod
    def find_user(cls, user_id):
        user = cls.query.filter_by(user_id=user_id).first()
        if user:
            return user
        return None

    @classmethod
    def find_by_login(cls, login):
        user = cls.query.filter_by(login=login).first()
        if user:
            return user
        return None

    @classmethod
    def find_by_email(cls, email):
        user = cls.query.filter_by(email=email).first()
        if user:
            return user
        return None

    def save_user(self):
        database.session.add(self)
        database.session.commit()

    def delete_user(self):
        database.session.delete(self)
        database.session.commit()
