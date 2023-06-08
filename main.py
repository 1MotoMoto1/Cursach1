from flask import redirect, render_template
from flask import Flask, render_template, url_for, request, flash, session
from flask_login import LoginManager, login_manager, UserMixin, login_required, login_user, logout_user, current_user
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import check_password_hash, generate_password_hash
from functools import wraps
from datetime import datetime

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///Priziv.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False

db = SQLAlchemy(app)
login_manager = LoginManager(app)


class Article(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    hirurg = db.Column(db.Text, nullable=False)
    nevrolog = db.Column(db.Text, nullable=False)
    okulist = db.Column(db.Text, nullable=False)
    stomatolog = db.Column(db.Text, nullable=False)
    terapevt = db.Column(db.Text, nullable=False)
    narkolog = db.Column(db.Text, nullable=False)
    psihiator = db.Column(db.Text, nullable=False)
    category = db.Column(db.Text, nullable=False)
    fio = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return '<Article %r>' % self.id


class Users(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    login = db.Column(db.Text, nullable=False, unique=True)
    password = db.Column(db.Text, nullable=False)
    role = db.Column(db.Text, nullable=False)

    def __repr__(self):
        return '<Users %r>' % self.id


@login_manager.user_loader
def load_user(user_id):
    return Users.query.get(user_id)


@app.route('/login', methods=['GET', 'POST'])
def login_page():
    login = request.form.get('login')
    password = request.form.get('password')
    if login and password:
        user = Users.query.filter_by(login=login).first()
        if user and check_password_hash(user.password, password):
            login_user(user)
            session['user'] = True
            return redirect('/')
        else:
            flash('Error')
    else:
        flash('Заполните поля')
    return render_template('login.html')



@app.route('/register', methods=['GET', 'POST'])
def register():
    login = request.form.get('login')
    password = request.form.get('password')
    password2 = request.form.get('password')
    role = request.form.get('role')
    if not (login or password or password2):
        flash('Please fields')
    elif password != password2:
        flash('BBBBB')
    else:

        hash_pwd = generate_password_hash(password)
        new_user = Users(login=login, password=hash_pwd, role=role)
        db.session.add(new_user)
        db.session.commit()

        return redirect(url_for('login_page'))
    return render_template('register.html')


@app.route('/logout', methods=['GET', 'POST'])
def logout():
    logout_user()
    session.pop('user', None)
    return redirect(url_for('login_page'))


@app.after_request
def redirect_to_signin(response):
    if response.status_code == 401:
        return redirect(url_for('login_page') + '?next=' + request.url)
    return response


@app.route('/')
@login_required
def index():
    return render_template("index.html")


@app.route('/create-article', methods=['POST', 'GET'])
@login_required
def create_article():
    if request.method == "POST":
        hirurg = request.form['hirurg']
        nevrolog = request.form['nevrolog']
        okulist = request.form['okulist']
        stomatolog = request.form['stomatolog']
        terapevt = request.form['terapevt']
        narkolog = request.form['narkolog']
        psihiator = request.form['psihiator']
        category = request.form['category']
        fio = request.form['fio']

        article = Article(hirurg=hirurg, nevrolog=nevrolog, okulist=okulist, stomatolog=stomatolog,
                          terapevt=terapevt, narkolog=narkolog, psihiator=psihiator, category=category, fio=fio, )

        try:
            db.session.add(article)
            db.session.commit()
            return redirect('/')
        except:
            return "Error"
    else:
        return render_template("create-article.html")


@app.route('/posts')
@login_required
def posts():
    articles = Article.query.order_by(Article.fio).all()

    return render_template("posts.html", articles=articles)


@app.route('/posts/<int:id>')
@login_required
def post_detail(id):
    article = Article.query.get(id)

    return render_template("post_detail.html", article=article)


@app.route('/posts/<int:id>/update', methods=['POST', 'GET'])
@login_required
def post_update(id):
    article = Article.query.get(id)
    if request.method == "POST":
        article.hirurg = request.form['hirurg']
        article.nevrolog = request.form['nevrolog']
        article.okulist = request.form['okulist']
        article.stomatolog = request.form['stomatolog']
        article.terapevt = request.form['terapevt']
        article.narkolog = request.form['narkolog']
        article.psihiator = request.form['psihiator']
        article.category = request.form['category']
        article.fio = request.form['fio']

        try:
            db.session.commit()
            return redirect('/posts')
        except:
            return "Error"
    else:
        article = Article.query.get(id)
        return render_template("post_update.html", article=article)


##################################################################################
@app.route('/hirurg')

def hirurg():
    art = Article.query.order_by(Article.fio).all()

    return render_template("hirurg.html", art=art)

@app.route('/hirurg/<int:id>')
@login_required
def hirurg_detail(id):
    arte = Article.query.get(id)

    return render_template("hirurg.detail.html", arte=arte)

@app.route('/hirurg/<int:id>/up', methods=['POST', 'GET'])
@login_required
def hirurg_update(id):
    article = Article.query.get(id)
    if request.method == "POST":
        article.hirurg = request.form['hirurg']
        try:
            db.session.commit()
            return redirect('/hirurg')
        except:
            return "Error"
    else:
        article = Article.query.get(id)
        return render_template("hirurg_update.html", article=article)
#########################################################################################
@app.route('/nevrolog')
@login_required
def nevrolog():
    nev = Article.query.order_by(Article.fio).all()

    return render_template("nevrolog.html", nev=nev)


@app.route('/nevrolog/<int:id>')
@login_required
def nevrolog_detail(id):
    nevrolog = Article.query.get(id)

    return render_template("nevrolog_detail.html", nevrolog=nevrolog)

@app.route('/nevrolog/<int:id>/up', methods=['POST', 'GET'])
@login_required
def nevrolog_update(id):
    article = Article.query.get(id)
    if request.method == "POST":
        article.nevrolog = request.form['nevrolog']
        try:
            db.session.commit()
            return redirect('/nevrolog')
        except:
            return "Error"
    else:
        article = Article.query.get(id)
        return render_template("nevrolog_update.html", article=article)
#########################################################################################
@app.route('/okulist')
@login_required
def okulist():
    oku = Article.query.order_by(Article.fio).all()

    return render_template("okulist.html", oku=oku)


@app.route('/okulist/<int:id>')
@login_required
def okulist_detail(id):
    okulist = Article.query.get(id)

    return render_template("okulist_detail.html", okulist=okulist)

@app.route('/okulist/<int:id>/up', methods=['POST', 'GET'])
def okulist_update(id):
    article = Article.query.get(id)
    if request.method == "POST":
        article.okulist = request.form['okulist']
        try:
            db.session.commit()
            return redirect('/okulist')
        except:
            return "Error"
    else:
        article = Article.query.get(id)
        return render_template("okulist_update.html", article=article)
#########################################################################################
@app.route('/stomatolog')
@login_required
def stomatolog():
    ter = Article.query.order_by(Article.fio).all()

    return render_template("stomatolog.html", ter=ter)


@app.route('/stomatolog/<int:id>')
@login_required
def stomatolog_detail(id):
    stomatolog = Article.query.get(id)

    return render_template("stomatolog_detail.html", stomatolog=stomatolog)

@app.route('/stomatolog/<int:id>/up', methods=['POST', 'GET'])
@login_required
def stomatolog_update(id):
    article = Article.query.get(id)
    if request.method == "POST":
        article.stomatolog = request.form['stomatolog']
        try:
            db.session.commit()
            return redirect('/stomatolog')
        except:
            return "Error"
    else:
        article = Article.query.get(id)
        return render_template("stomatolog_update.html", article=article)
#########################################################################################
@app.route('/terapevt')
@login_required
def terapevt():
    ter = Article.query.order_by(Article.fio).all()

    return render_template("terapevt.html", ter=ter)


@app.route('/terapevt/<int:id>')
@login_required
def terapevt_detail(id):
    terapevt = Article.query.get(id)

    return render_template("terapevt_detail.html", terapevt=terapevt)

@app.route('/terapevt/<int:id>/up', methods=['POST', 'GET'])
@login_required
def terapevt_update(id):
    article = Article.query.get(id)
    if request.method == "POST":
        article.terapevt = request.form['terapevt']
        try:
            db.session.commit()
            return redirect('/terapevt')
        except:
            return "Error"
    else:
        article = Article.query.get(id)
        return render_template("terapevt_update.html", article=article)
#########################################################################################
@app.route('/narkolog')
@login_required
def narkolog():
    nar = Article.query.order_by(Article.fio).all()

    return render_template("narkolog.html", nar=nar)


@app.route('/narkolog/<int:id>')
@login_required
def narkolog_detail(id):
    narkolog = Article.query.get(id)

    return render_template("narkolog_detail.html", narkolog=narkolog)

@app.route('/narkolog/<int:id>/up', methods=['POST', 'GET'])
@login_required
def narkolog_update(id):
    article = Article.query.get(id)
    if request.method == "POST":
        article.narkolog = request.form['narkolog']
        try:
            db.session.commit()
            return redirect('/narkolog')
        except:
            return "Error"
    else:
        article = Article.query.get(id)
        return render_template("narkolog_update.html", article=article)
#########################################################################################

@app.route('/psihiator')
@login_required
def psihiator():
    psi = Article.query.order_by(Article.fio).all()

    return render_template("psihiator.html", psi=psi)


@app.route('/psihiator/<int:id>')
@login_required
def psihiator_detail(id):
    psihiator = Article.query.get(id)

    return render_template("psihiator_detail.html", psihiator=psihiator)

@app.route('/psihiator/<int:id>/up', methods=['POST', 'GET'])
@login_required
def psihiator_update(id):
    article = Article.query.get(id)
    if request.method == "POST":
        article.psihiator = request.form['psihiator']
        try:
            db.session.commit()
            return redirect('/psihiator')
        except:
            return "Error"
    else:
        article = Article.query.get(id)
        return render_template("psihiator_update.html", article=article)
#########################################################################################
@app.route('/base')
def base():
    return render_template("base.html")

if __name__ == "__main__":
    app.secret_key = 'some secret salt'
    app.run(debug=True)
