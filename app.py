from flask import Flask, request, redirect, render_template, url_for, flash, session
from flask_mysqldb import MySQL, MySQLdb
from datetime import timedelta
import config
from werkzeug.security import generate_password_hash, check_password_hash
import re
from functools import wraps


app = Flask(__name__)
app.secret_key = 'd5fb8c4fa8bd46638dadc4e751e0d68d'
app.config['PERMANENT_SESSION_LIFETIME'] = timedelta(minutes=10)


#Conexion a BD
app.config['SECRET_KEY'] = config.HEX_SEC_KEY
app.config['MYSQL_HOST'] = config.MYSQL_HOST
app.config['MYSQL_USER'] = config.MYSQL_USER
app.config['MYSQL_PASSWORD'] = config.MYSQL_PASSWORD
app.config['MYSQL_DB'] = config.MYSQL_DB
mysql = MySQL(app)

#Funcion para validar Emails
def es_email_valido(e):
    patron_email = r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$'
    return re.match(patron_email, e) is not None
#Funcion para obtener datos de usuario
def obtener_datos_usuario(email):
    cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cursor.execute("SELECT * FROM users WHERE email = %s", (email,))
    user = cursor.fetchone()
    cursor.close()
    return user
#Funcion para obtener lista de paises
def obtener_paises():
    cur = mysql.connection.cursor()
    cur.execute("SELECT name_country FROM countries")  
    country = cur.fetchall()
    cur.close()
    return country


#HOME
@app.route('/')
def home():
    return render_template('index.html')


#REGISTRO
@app.route('/register', methods=['GET', 'POST'])
def register():
    if 'id_user' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']
        password_confirmation = request.form['password_confirmation']

        if not es_email_valido(email):
            flash('Introduce un Email valido.')
            return redirect(url_for('register'))
        
        if password != password_confirmation:
            flash('Las contraseñas no coinciden.')
            return redirect(url_for('register'))

        # Verificar si el usuario ya existe
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cur.execute("SELECT * FROM users WHERE email = %s", [email])
        existing_user = cur.fetchone()
        if existing_user:
            flash('El Email ya está en uso.')
            return redirect(url_for('register'))

        # Insertar el nuevo usuario en la base de datos
        password_hash = generate_password_hash(password, method='pbkdf2:sha256')
        cur.execute("INSERT INTO users (email, password) VALUES (%s, %s)", (email, password_hash))

        # Obtener el ID del usuario recién creado
        cur.execute("SELECT id_user FROM users WHERE email = %s", [email])
        new_user = cur.fetchone()

        if new_user:
            # Establecer el saldo inicial de la billetera
            initial_balance = 0  # o cualquier otro valor que desees como saldo inicial

            # Crear una nueva billetera para el usuario
            cur.execute("INSERT INTO wallets (balance, id_user) VALUES (%s, %s)", (initial_balance, new_user['id_user']))
            mysql.connection.commit()
            cur.close()
          

        flash('Registro exitoso.')
        return redirect(url_for('login'))
    
    return render_template('register.html')


#LOGIN
@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'id_user' in session:
        return redirect(url_for('dashboard'))
    
    if request.method == 'POST':
        email = request.form['email']
        password = request.form['password']

        # Verificar si el usuario existe
        cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)  # Utiliza DictCursor
        cur.execute("SELECT * FROM users WHERE email = %s", [email])
        user = cur.fetchone()

        if user:
            # Verificar la contraseña
            password_hash = user['password']
            if check_password_hash(password_hash, password):
                user = obtener_datos_usuario(email)

                session['role'] = user['role']
                session['id_user'] = user['id_user']
                session['email'] = user['email']
                session['nombre'] = user['nombre']
                session['apellido'] = user['apellido']
                session.permanent = True  # Hace que la sesión sea permanente
                flash('Has iniciado sesión exitosamente.')
                return redirect(url_for('dashboard'))  # Redirigir al usuario a la página de dashboard
            else:
                flash('El Email o la Contraseña son incorrectos.')
        else:
            flash('El Email o la Contraseña son incorrectos.')

        return redirect(url_for('dashboard'))

    return render_template('login.html')


#LOGOUT
@app.route('/logout')
def logout():
    # Remueve los datos de la sesión para cerrar la sesión del usuario
    session.clear()
    flash('Vuelve pronto.')
    return redirect(url_for('login'))


#DASHBOARD
@app.route('/dashboard')
def dashboard():
    if 'role' not in session:
        flash("Inicia sesion para acceder.")
        return redirect(url_for('login'))
    if session['role'] == 'admin':
        return render_template('dashboard_admin.html')
    elif session['role'] == 'merchant':
        return render_template('dashboard_merchant.html')
    else:
        return render_template('dashboard.html')


#GESTION DE USUARIOS ADMINISTRADOR
@app.route('/gestion_usuarios')
def gestion_usuarios():
    if 'id_user' not in session or session['role'] != 'admin':
        flash('Acceso denegado.')
        return redirect(url_for('login'))

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT * FROM users")  # Suponiendo que tienes una tabla 'users'
    users = cur.fetchall()
    cur.close()

    return render_template('gestion_usuarios.html', users=users)


#EDITAR USUARIOS ADMINISTRADOR
@app.route('/editar_usuario/<int:id_user>', methods=['GET', 'POST'])
def editar_usuario(id_user):
    if 'id_user' not in session or session['role'] != 'admin':
        flash('Acceso denegado.')
        return redirect(url_for('login'))

    country = obtener_paises()

    if request.method == 'POST':
        # Aquí iría la lógica para procesar los datos actualizados del formulario
        email = request.form['email']
        nombre = request.form['nombre']
        apellido = request.form['apellido']
        telefono = request.form['telefono']
        pais = request.form['pais']
        direccion = request.form['direccion']
        role = request.form['role']

        # Aquí debes incluir la lógica para actualizar los datos en la base de datos
        cur = mysql.connection.cursor()
        cur.execute("""
            UPDATE users 
            SET email=%s, nombre=%s, apellido=%s, telefono=%s, pais=%s, direccion=%s, role=%s 
            WHERE id_user=%s
            """, (email, nombre, apellido, telefono, pais, direccion, role, id_user))
        mysql.connection.commit()
        cur.close()

        flash('Información del usuario actualizada correctamente.')
        return redirect(url_for('gestion_usuarios'))

    # Aquí iría la lógica para obtener los datos actuales del usuario y mostrarlos en el formulario
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT * FROM users WHERE id_user = %s", (id_user,))
    user = cur.fetchone()
    cur.close()
    return render_template('editar_usuario.html', user=user, country=country, id_user=id_user)


#ELIMINAR USUARIO ADMINISTRADOR
@app.route('/eliminar_usuario/<int:id_user>', methods=['POST'])
def eliminar_usuario(id_user):
    if 'id_user' not in session or session['role'] != 'admin':
        flash('Acceso denegado.', 'danger')
        return redirect(url_for('login'))
    
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)  # Utiliza DictCursor
    cur.execute("DELETE FROM users WHERE id_user = %s", (id_user,))
    mysql.connection.commit()
    cur.close()
    flash('Usuario eliminado correctamente.', 'success')
    return redirect('/gestion_usuarios')



#MODIFICAR DATOS DE USUARIO CLIENTES
@app.route('/modificar_usuario', methods=['GET', 'POST'])
def modificar_usuario():
    if 'id_user' not in session or session['role'] != 'admin':
        flash('Acceso denegado.')
        return redirect(url_for('login'))

    email = session['email']
    country = obtener_paises()

    if request.method == 'POST':
        # Recuperar los datos del formulario
        nombre = request.form['nombre']
        apellido = request.form['apellido']
        telefono = request.form['telefono']
        pais = request.form['pais']
        direccion = request.form['direccion']

        # Aquí debes incluir la lógica para actualizar los datos en la base de datos
        cur = mysql.connection.cursor()
        cur.execute("""
            UPDATE users 
            SET nombre=%s, apellido=%s, telefono=%s, pais=%s, direccion=%s 
            WHERE email=%s
            """, (nombre, apellido, telefono, pais, direccion, email))
        mysql.connection.commit()
        cur.close()

        user = obtener_datos_usuario(email)
        session['nombre'] = user['nombre']
        session['apellido'] = user['apellido']
        session['telefono'] = user['telefono']
        session['pais'] = user['pais']
        session['direccion'] = user['direccion']

        flash('Información del usuario actualizada correctamente.')
        return redirect(url_for('modificar_usuario'))

    # Si el método es GET, recuperamos la información actual del usuario para mostrarla en el formulario
    # Suponiendo que tienes una función que obtiene los datos del usuario por email
    user = obtener_datos_usuario(email)
    return render_template('modificar_usuario.html', country=country, user=user)


#AGREGAR CUENTAS CLIENTES
@app.route('/accounts', methods=['GET', 'POST'])
def accounts():
    if 'id_user' not in session or session['role'] != 'admin':
        flash('Acceso denegado.')
        return redirect(url_for('login'))
    
    id_user = session.get('id_user')  # Obtener el id de la sesión

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)  # Utiliza DictCursor
    cur.execute("SELECT * FROM cuentas WHERE user_id = %s", [id_user])
    cuentas = cur.fetchall()
    cur.close()

    if request.method == 'POST':
        id_user = session.get('id_user')  # Asume que el user_id está en la sesión
        account = request.form['account']
        type = request.form['type']
        number = request.form['number']
        email = request.form['email']
        notas = request.form['notas']

        cur = mysql.connection.cursor()
        cur.execute("INSERT INTO cuentas (user_id, account, type, number, email, notas) VALUES (%s, %s, %s, %s, %s, %s)", (id_user, account, type, number, email, notas))
        mysql.connection.commit()
        cur.close()

        flash('Cuenta agregada exitosamente')
        return redirect(url_for('accounts'))

    return render_template('accounts.html', cuentas=cuentas)


#EDITAR CUENTAS BANCARIAS CLIENTES
@app.route('/editar_cuenta/<int:id_cuenta>', methods=['GET', 'POST'])
def editar_cuenta(id_cuenta):
    if 'id_user' not in session or session['role'] != 'admin':
        flash('Acceso denegado.')
        return redirect(url_for('login'))
    
    if request.method == 'POST':
        # Aquí iría la lógica para procesar los datos del formulario de edición.
        account = request.form.get('account')
        tipo = request.form.get('type')
        number = request.form.get('number')
        email = request.form.get('email')
        notas = request.form.get('notas')

        cur = mysql.connection.cursor()
        cur.execute("""
            UPDATE cuentas 
            SET account=%s, type=%s, number=%s, email=%s, notas=%s 
            WHERE id_cuenta=%s
            """, (account, tipo, number, email, notas, id_cuenta))
        mysql.connection.commit()
        cur.close()

        return redirect(url_for('accounts'))

    # Obtener los datos actuales de la cuenta a editar.
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)  # Utiliza DictCursor
    cur.execute("SELECT * FROM cuentas WHERE id_cuenta = %s", [id_cuenta])
    cuenta = cur.fetchone()
    cur.close()

    return render_template('editar_cuenta.html', cuenta=cuenta)


#ELIMINAR CUENTA BANCARIAS CLIENTES
@app.route('/eliminar_cuenta/<int:id_cuenta>')
def eliminar_cuenta(id_cuenta):
    if 'id_user' not in session or session['role'] != 'admin':
        flash('Acceso denegado.')
        return redirect(url_for('login'))
    
    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)  # Utiliza DictCursor
    cur.execute("DELETE FROM cuentas WHERE id_cuenta = %s", [id_cuenta])
    mysql.connection.commit()
    cur.close()
    flash('Cuenta eliminada exitosamente.')
    return redirect('/accounts')

@app.route('/wallet')
def wallet():
    if 'id_user' not in session:
        return redirect(url_for('login'))

    id_user = session['id_user']

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT balance FROM wallets WHERE id_user = %s", (id_user,))
    balance = cur.fetchone()

    cur.execute("SELECT * FROM transactions WHERE id_user = %s ORDER BY timestamp DESC", (id_user,))
    transactions = cur.fetchall()
    cur.close()

    return render_template('wallet.html', balance=balance, transactions=transactions)



@app.route('/add_funds', methods=['POST'])
def add_funds():
    if 'id_user' not in session:
        flash('Por favor, inicia sesión para continuar.', 'warning')
        return redirect(url_for('login'))

    id_user = session['id_user']
    amount = request.form.get('amount', type=float)

    if amount <= 0:
        flash('Por favor, introduce una cantidad válida.', 'danger')
        return redirect(url_for('wallet'))

    # Lógica para actualizar el saldo en la base de datos
    cur = mysql.connection.cursor()
    cur.execute("UPDATE wallets SET balance = balance + %s WHERE id_user = %s", (amount, id_user))
    mysql.connection.commit()

    # Registra la transacción
    cur.execute("INSERT INTO transactions (id_user, type, amount) VALUES (%s, %s, %s)", 
                (id_user, 'deposit', amount))
    mysql.connection.commit()

    cur.close()
    flash('Fondos agregados exitosamente.', 'success')
    return redirect(url_for('wallet'))



@app.route('/withdraw_funds', methods=['POST'])
def withdraw_funds():
    if 'id_user' not in session:
        flash('Por favor, inicia sesión para continuar.', 'warning')
        return redirect(url_for('login'))

    id_user = session['id_user']
    amount = request.form.get('amount', type=float)

    if amount <= 0:
        flash('Por favor, introduce una cantidad válida.', 'danger')
        return redirect(url_for('wallet'))

    # Verifica si el usuario tiene suficientes fondos

    cur = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
    cur.execute("SELECT balance FROM wallets WHERE id_user = %s", (id_user,))
    current_balance = cur.fetchone()['balance']

    if amount > current_balance:
        cur.close()
        flash('Fondos insuficientes.', 'danger')
        return redirect(url_for('wallet'))

    # Lógica para actualizar el saldo en la base de datos
    cur.execute("UPDATE wallets SET balance = balance - %s WHERE id_user = %s", (amount, id_user))
    mysql.connection.commit()

    # Registra la transacción
    cur.execute("INSERT INTO transactions (id_user, type, amount) VALUES (%s, %s, %s)", 
                (id_user, 'withdrawal', amount))
    mysql.connection.commit()

    cur.close()
    flash('Fondos retirados exitosamente.', 'success')
    return redirect(url_for('wallet'))


if __name__ == '__main__':
    app.run(debug=True)
