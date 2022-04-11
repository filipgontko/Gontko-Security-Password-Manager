import sqlite3

from backend.my_logger import logger


def create_table():
    """
    Create table for storing master key hash and e-mail address it's connected with.
    :return: bool: True if successful, False otherwise.
    """
    try:
        sqlite_conn = connect_db()
        cursor = sqlite_conn.cursor()
        create_table_query = """CREATE TABLE IF NOT EXISTS master_table (
                        master_key_hash TEXT,
                        email TEXT
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


def insert_master_information(master_key_hash, email):
    """
    Insert information into the database.
    :param email: E-mail address of the account connected to the master key.
    :param master_key_hash: Master key hash.
    :return: bool: True if successful, False otherwise.
    """
    try:
        sqlite_conn = connect_db()
        cursor = sqlite_conn.cursor()
        insert_query = """INSERT INTO master_table(master_key_hash, email) 
                       VALUES ('{}', '{}');""".format(master_key_hash, email)
        cursor.execute(insert_query)
        sqlite_conn.commit()
        cursor.close()
    except sqlite3.Error as error:
        logger.error("Error while inserting - {}".format(error))
    finally:
        disconnect_db(sqlite_conn)


def edit_master_information(email, master_key_hash_new):
    """
    Edit master key for an account. Hash (PBKDF2-SHA-256) of the new master key will be stored.
    :param email: E-mail of the account connected to the master key.
    :param master_key_hash_new: New master key hash.
    :return: bool: True if successful, False otherwise.
    """
    try:
        sqlite_conn = connect_db()
        cursor = sqlite_conn.cursor()
        update_query = """UPDATE master_table 
                        SET master_key = '{}' 
                        WHERE email = '{}'""".format(master_key_hash_new, email)
        cursor.execute(update_query)
        sqlite_conn.commit()
        cursor.close()
    except sqlite3.Error as error:
        logger.error("Error while updating password - {}".format(error))
    finally:
        disconnect_db(sqlite_conn)


def get_master_key_hash(email):
    """
    Get the master key hash for the specified account.
    :param email: E-mail address of the account for which to retrieve the master key hash.
    :return: Hashed master key
    """
    try:
        sqlite_conn = connect_db()
        cursor = sqlite_conn.cursor()
        total_query = """SELECT master_key_hash FROM master_table
                      WHERE email = '{}'""".format(email)
        cursor.execute(total_query)
        record = cursor.fetchone()[0]
        return record
    except sqlite3.Error as error:
        print("Error while connecting to the DB - {}".format(error))
    finally:
        disconnect_db(sqlite_conn)


def check_user_record_exists(email):
    """
    Check if the specified user exists.
    :param email: E-mail address of the account which needs to be checked for existence.
    :return: True if user with the e-mail address exists, False otherwise.
    """
    try:
        sqlite_conn = connect_db()
        cursor = sqlite_conn.cursor()
        total_query = """SELECT EXISTS (SELECT 1 FROM master_table
                          WHERE email = '{}'""".format(email)
        cursor.execute(total_query)
        record = cursor.fetchone()[0]
        return record
    except sqlite3.Error as error:
        print("Error while connecting to the DB - {}".format(error))
    finally:
        disconnect_db(sqlite_conn)


def clear_table():
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
