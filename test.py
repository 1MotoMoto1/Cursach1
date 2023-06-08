import json
import tempfile
import main
import os

import test

try:
    from main import app,Users,db,Article
    import unittest
except Exception as e:
    print("Error".format(e))

class Flask_Test(unittest.TestCase):
        def setUp(self):
            self.db_fd, main.app.config['DATABASE'] = tempfile.mkstemp()
            self.app = main.app.test_client()
            main.init_db()


        def tearDown(self):
            os.close(self.db_fd)
            os.unlink(main.app.config['DATABASE'])


        def test_empty_db(self):
            rv = self.app.get('/create-article')

            assert 'Ещё нет ни одно записи' in rv.data




###################################################################
    def test_login_logout(self):
        rv = self.login('Markus', '123')
        assert 'You were logged in' in rv.data
        rv = self.logout()
        assert 'You were logged out' in rv.data
        rv = self.login('Markiz', '123')
        assert 'Invalid username' in rv.data


#####################################################################################
    def pers_is_valid(self):
        data_test = {
            'hirurg':'dsad',
            'nevrolog': 'dasd',
            'okulist': 'dsad',
            'stomatolog': 'dsad',
            'terapevt': 'dsad',
            'narkolog': 'dsad',
            'psihiator': 'dsad',
            'fio': 'dsad',
            'date': '13.05.2022'
        }
        form = Valid(data = data_test)
        self.assertTrue(form.is_valid)
#####################################################################################
    def login(self, username, password):
        return self.app.post('/login', data=dict(
            username=username,
            password=password
        ), follow_redirects=True)

    def logout(self):
        return self.app.get('/base', follow_redirects=True)

#####################################################################################
    def test_view(self):
        resp = app.client.get("/")
        self.assertEqual(resp.status_code, 200)
        self.assertTemplateUsed(resp,'login/index.html')

#####################################################################################

    def test(self):
        tester = app.test_client(self)
        response = tester.get("/")
        statuscode = response.status_code
        self.assertEqual(statuscode,302)
########Возвращает тип данных при вызове функции

    def test1(self):
        tester = app.test_client(self)
        response = tester.get("/login_page")
        self.assertEqual(response.content_type, "text/html; charset=utf-8")


