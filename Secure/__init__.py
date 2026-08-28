import pymysql
# Patch version so Django 4.x's mysqlclient check passes
pymysql.version_info = (1, 4, 6, "final", 0)
pymysql.__version__ = "1.4.6"
pymysql.install_as_MySQLdb()