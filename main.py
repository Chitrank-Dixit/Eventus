# flask minimal application
import flask, flask.views
 #from flask import Flask, render_template
#import flask.request
#from flask.views import MethodView
import os
app = flask.Flask(__name__)

app.secret_key = "uscore"

class View(flask.views.MethodView):
    def get(self):
        return flask.render_template('index.html')

    def post(self):
        result = eval(flask.request.form['expression'])
        flask.flash(result)
        return self.get()
        

app.add_url_rule('/',view_func=View.as_view('main'),methods=['GET','POST'])

app.debug = True
app.run()

