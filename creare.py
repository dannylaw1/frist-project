import mysql.connector

mydb = mysql.connector.connect(
    host="localhost",
    user="root",
    passwd="mysql"
)

my_cursor = mydb.cursor()

# Create a new user
my_cursor.execute("CREATE USER 'new'@'localhost' IDENTIFIED BY 'password'")
my_cursor.execute("GRANT ALL PRIVILEGES ON *.* TO 'new'@'localhost' WITH GRANT OPTION")

mydb.commit()
my_cursor.close()
mydb.close()
