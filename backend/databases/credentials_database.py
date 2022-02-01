import sqlite3

from backend.my_logger import logger


def create_table():
    """
    Create table for storing username, password and site.
    :return: bool: True if successful, False otherwise.
    """
    try:
        sqlite_conn = connect_db()
        cursor = sqlite_conn.cursor()
        create_table_query = """CREATE TABLE IF NOT EXISTS credentials_table (
                        site TEXT,
                        username TEXT,
                        password TEXT
                        );"""
        cursor.execute(create_table_query)
        sqlite_conn.commit()
        cursor.close()

    except sqlite3.Error as error:
        logger.error("Error while connecting to the DB - {}".format(error))
    finally:
        disconnect_db(sqlite_conn)


def connect_db():
    """
    Connect to the DB
    :return: None
    """
    try:
        sqlite_conn = sqlite3.connect('pwdmngrdb.db')
        return sqlite_conn
    except sqlite3.Error as error:
        logger.error("Error while connecting to the DB - {}".format(error))


def disconnect_db(conn):
    """
    Disconnect from the DB if connection exists
    :param conn: DB connection
    :return: None
    """
    if conn:
        conn.close()


def insert_credentials(credentials):
    """
    Insert credentials into the database.
    :param credentials: Credentials object for which to store username and password
    :return: bool: True if successful, False otherwise.
    """
    try:
        sqlite_conn = connect_db()
        cursor = sqlite_conn.cursor()
        insert_query = """INSERT INTO credentials_table(site, username, password) 
                       VALUES ('{}', '{}', {});""".format(credentials.site, credentials.username, credentials.password)
        cursor.execute(insert_query)
        sqlite_conn.commit()
        cursor.close()
    except sqlite3.Error as error:
        logger.error("Error while inserting - {}".format(error))
    finally:
        disconnect_db(sqlite_conn)


# TODO: Password history should be accessible at least for the last 3 passwords per site.
# TODO: Edit all credentials should be poosible.

def edit_password(credentials):
    """
    Edit the credential for a specific site. Change either credential is possible.
    :param credentials: Credentials object for which to store username and password
    :return: bool: True if successful, False otherwise.
    """
    try:
        sqlite_conn = connect_db()
        cursor = sqlite_conn.cursor()
        update_query = """UPDATE credentials_table 
                        SET password = '{}' 
                        WHERE site = '{}' AND username = '{}'""".format(credentials.password, credentials.site,
                                                                        credentials.username)
        cursor.execute(update_query)
        sqlite_conn.commit()
        cursor.close()
    except sqlite3.Error as error:
        logger.error("Error while updating password - {}".format(error))
    finally:
        disconnect_db(sqlite_conn)


def get_password(credentials):
    """
    Get the password for a specific site.
    :param credentials: Credentials object for which to retrieve the password.
    :return: Encrypted password
    """
    try:
        sqlite_conn = connect_db()
        cursor = sqlite_conn.cursor()
        total_query = """SELECT password FROM credentials_table
                      WHERE site = '{}' AND username = '{}'""".format(credentials.site, credentials.username)
        cursor.execute(total_query)
        record = cursor.fetchone()[0]
        return record
    except sqlite3.Error as error:
        print("Error while connecting to the DB - {}".format(error))
    finally:
        disconnect_db(sqlite_conn)


def clear_db():
    """
    Clear all credential information.
    :return: bool: True if successful, False otherwise.
    """
    try:
        sqlite_conn = connect_db()
        cursor = sqlite_conn.cursor()
        delete_query = "DELETE FROM master_key_db"
        cursor.execute(delete_query)
        sqlite_conn.commit()
        cursor.close()
    except sqlite3.Error as error:
        logger.error("Error while connecting to the DB - {}".format(error))
    finally:
        disconnect_db(sqlite_conn)
