from flask.templating import Environment
# import sqlalchemy


class Config(object):
    DEBUG=False
    TESTING=False
    SECRET_KEY = "my_top_secret_key"
    SQLALCHEMY_TRACK_MODIFICATIONS = True


class DevelopmentConfig(Config):
    Environment='development'
    DEBUG=True
    SESSION_COOKIE_SECURE = False
    TESTING=True
