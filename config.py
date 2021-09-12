class Config(object):
    DEBUG=False
    TESTING=False
    SECRET_KEY = "my_top_secret_key"


class DevelopmentConfig(Config):
    DEBUG=True
    SESSION_COOKIE_SECURE = False
    TESTING=True
