Google Cloud Platform Development
=======================================

Application Type
------------------
#### Enterprise/Small Business Solutions , Education, Not for Profit

Criteria
------------------
- All submissions must have an appspot.com domain with a url in the following format: gcdc2013-<app-name>.appspot.com.
- Effective Use of Google App Engine (Compulsory)
    - All submissions must have an appspot.com domain
- Originality of Concept
- Relevance to Region (SSA, LATAM, India, SEA, MENA)
- Polish and Appeal
- Usability on multiple screen sizes
- Accessibility
- Indispensability: Is the application compelling and/or essential?
- Amount of user interactions on their app (comments, +1s, FB Likes etc)
- Google+ Sign-In / Integration (Not compulsory:Bonus Points)
- Creative use of Youtube and Google Maps APIs (Not compulsory:Bonus Points)
- Use of other Google platforms/APIs (Not compulsory:Bonus Points)

Competition Timelines
---------------------

- September 4th: Competition begins
- October 22nd: Submissions window opens
- November 21st: First round submissions due
- December 5th: Semi-Finalists announced
- January 5th: Updated Semi-Final Apps re-submitted
- January 28th: Winners announced


Judging & Awards
----------------

#### First Round:

By November 21st, all apps entering the competition must be submitted for judging. At most 10 apps from each of the 2 categories in all 6 regions (at most 20 apps total per region) will move to the semi-finals. Applications will be evaluated and ranked by a team of Google-selected internal and external judges. On December 5th, the apps moving to the semi-finals in each region will be announced.

#### Semi-Finals:

Those developers whose applications are selected for the semi-finals will have about one month to improve their applications (add features, improve stability, performance, etc). By January 5th, developers in the semi-finals will submit the final versions of their apps for judging via this website.

At the end of the judging period, all applications in each region and category will be evaluated and ranked by a team of Google-selected judges and announced on January 28th.

#### Awards:

Prizes will be distributed as follows; all prizes are in USD:

- Round One: All teams that make it to the semi-finals in each category in each region will be awarded Android devices.
- Round One: In order to encourage participation from women and highlight innovations from women in the developing markets, we are adding an additional prize. If a Semi-Finalist happens to be an individual or a team consisting solely of women, that team will be awarded an additional prize of $2000 USD.
- Round One: Any university team made up entirely of student or staff of a university (identified by the university domain email address) that makes it to the semi-finals will get $1,000.
- Semi-Finals: 1st prize in each category in each region will receive $20,000. This means that there will be a total of 12 grand prize winners
- Semi-Finals: If any team from a university wins the competition in any of the categories, the department to which the members of the team belong will win $18,000.
- At most 6 mentors (one from each region) will win an all expense paid trip to a major developer conference anywhere in the world to the tune of $5,000.

Results
------------

Information about the winning developers and Apps will be posted to this website on or around the following dates:

- Semi-Final Round: December 5th
- Winners: January 28th


Downloads
===========

Google Datastore for local testing :
------------------------------------
- https://developers.google.com/datastore/docs/downloads (install 'googledatastore' python package as well to interact with Google Cloud Datastore

 
Google + Sign Feature Help Links:
------------------------------------
- https://developers.google.com/+/
- https://developers.google.com/+/quickstart/python (follow simple steps)
- https://developers.google.com/api-client-library/python/start/installation (client API that interacts with main server of G+)
- https://pypi.python.org/pypi/Flask-KVSession (cookie based session management in Flask)
- http://stackoverflow.com/questions/10271110/python-oauth2-login-with-google
- http://stackoverflow.com/questions/3858772/how-to-use-virtualenv-with-google-app-engine-sdk-on-mac-os-x-10-6
- http://stackoverflow.com/questions/16505094/python-virtualenv-module-not-being-imported
- http://stackoverflow.com/questions/9499286/using-google-oauth2-with-flask
- http://stackoverflow.com/questions/11751972/new-to-flask-and-flask-login-importerror-no-module-named-login (one of the prominent one)
- https://flask-login.readthedocs.org/en/latest/ (Flask-Login)
- This is one of the best app I have seen with all socio integration using flask (https://bitbucket.org/chitrank_dixit/gae-init).


Flask Good practices
-------------------------
- http://www.realpython.com/blog/python/testing-in-django-part-2-model-mommy-vs-django-testing-fixtures/#.UjdCvlEW0T8
- http://www.realpython.com/blog/python/python-web-applications-with-flask-part-ii-app-creation/#.UjdCtlEW0T8
- Using Class based views: http://flask.pocoo.org/docs/views/
- We are using a better structured project here as per the Flask Good Practices says
- Best tutorial for all the stuff (http://blog.miguelgrinberg.com/post/the-flask-mega-tutorial-part-i-hello-world)
- http://ryaneshea.com/lightweight-python-apps-with-flask-twitter-bootstrap-and-heroku
- http://f.souza.cc/2010/08/flying-with-flask-on-google-app-engine.html

Using Google App Engine from virtualenv
---------------------------------------
- http://www.anler.me/blog/2012/jun/google-app-engine-in-virtualenv/
- http://monocaffe.blogspot.in/2013/04/python-virtualenv-for-google-app-engine.html
  or use this simple command each time (I prefer this fed up of making symbolic links and path creations so currently I am using this)
<pre class="console">
  export PATH=$PATH:/home/chitrank/google_appengine/
</pre>

Google App Engine Tutorials
--------------------------------------------
- http://www.appenginelearn.com/

Google Cloud Datastore (NoSQL DB made for scalability)
--------------------------------------------------------
- https://developers.google.com/datastore/docs/getstarted/
- https://developers.google.com/appengine/docs/python/datastore/
- https://developers.google.com/appengine/docs/python/datastore/queryclass

Redis (For Future Release as per learning more)
---------------------------------------------------
- redis.io

Google Cloud
--------------------------------------------------------
- Access Google Cloud Datastore from here( https://cloud.google.com/console#/project/apps~uscore-test/datastore/query)
- https://docs.google.com/document/d/1AefylbadN456_Z7BZOpZEXDq8cR8LYu7QgI7bt5V0Iw/mobilebasic
- https://developers.google.com/appengine/docs/python/ndb


Bootstrap 2 (for front end and responsiveness)
---------------------------------------------------------
- Bootstrap Select : http://silviomoreto.github.io/bootstrap-select/
- Bootstrap site: http://getbootstrap.com/2.3.2/
- Twitter Bootstrap (road to perfection):
http://twitter-bootstrap.node1.zygote.cc/#

Bootstrap Plugins
------------------------------------------------------
- http://tutorialzine.com/2013/07/50-must-have-plugins-for-extending-twitter-bootstrap/
- http://bootsnipp.com/resources
- http://www.eyecon.ro/bootstrap-datepicker/ (bootstrap datepicker)
- http://ivaynberg.github.io/select2/ (boostrap select alike )
- http://harvesthq.github.io/chosen/ ( bootstrap select alike ) 

Ajax with Python Flask
----------------------------
- http://runnable.com/UiPhLHanceFYAAAP/how-to-perform-ajax-in-flask-for-python
- http://www.giantflyingsaucer.com/blog/?p=4310

List_of_JavaScript Libraries
------------------------------------------------
- http://en.wikipedia.org/wiki/List_of_JavaScript_libraries
- For autocomplete while searching (http://complete-ly.appspot.com/).


Backbone.js Tutorials
------------------------------------------------
- http://backbonejs.org/
- http://addyosmani.github.io/backbone-fundamentals/
- http://backbonetutorials.com/
- interactive tutorials: http://chooseyourownapplication.com/chapters/intro
- http://arturadib.com/hello-backbonejs/docs/1.html

 
Knockout.js Tutorials
--------------------------------------------------
- http://learn.knockoutjs.com/#/?tutorial=intro
- interactive tutorials: http://chooseyourownapplication.com/chapters/intro
- http://www.knockmeout.net/
- http://pluralsight.com/training/Courses/TableOfContents?courseName=knockout-mvvm
- http://blog.stevensanderson.com/2010/07/12/editing-a-variable-length-list-knockout-style/
- https://github.com/carlhoerberg/knockout-websocket-example
- https://github.com/knockout/knockout/wiki/Recipes
- https://github.com/knockout/knockout/wiki/Plugins
- Building urls using knockout (http://www.softfinity.com/blog/an-simple-introduction-to-url-routing/)

Jquery Validation:
----------------------------------------------
- http://jqueryvalidation.org/
- http://reactiveraven.github.io/jqBootstrapValidation/
- http://jsfiddle.net/5WMff/

Making an API ( RESTful API ) for user with backbone.js
--------------------------------------------------------
- http://stackoverflow.com/questions/10182372/flask-with-backbone-js-rest-api
- http://blog.miguelgrinberg.com/post/designing-a-restful-api-with-python-and-flask
- http://blog.miguelgrinberg.com/post/designing-a-restful-api-using-flask-restful
- http://blog.miguelgrinberg.com/post/writing-a-javascript-rest-client (javascript rest client)

- http://flask.pocoo.org/docs/views/#method-based-dispatching

- http://blog.luisrei.com/

- http://blog.luisrei.com/articles/flaskrest.html

- http://blog.luisrei.com/articles/rest.html


HTML5 References
--------------------------
- Character references:http://dev.w3.org/html5/html-author/charref

Font Awesome (Icon package for bootstrap)
-----------------------------------------

JavaScript , JSON , AJAX, Jquery
-----------------------------------------
- refer w3schools.com and thenewboston videos at youtube, practice at Codeacademy.com
- jquery (http://api.jquery.com/), at W3schools and Head First JavaScript book
- AJAX:- at W3schools and Head First AJAX book
- JSON:- at jquery Documentation and 
- JavaScript ( Douglouas Crockford : JavaScript the Good Parts), https://developer.mozilla.org/en-US/docs/Web/JavaScript/Guide, Head First JavaScript


Tech Stack
--------------------
- Python Flask
- Google APIs
- Bootstrap 2
- Backbone.js (and its dependencies) or Knockoutjs 
- Google App Engine
- Google Cloud Datastore (NoSQL DB)
- Font Awesome, bootstrap-social-buttons

jinja2 template settings in Google App Engine
---------------------------------------------
- https://developers.google.com/appengine/docs/python/gettingstartedpython27/templates
_______________________________________________________________________________________


Flask on App Engine Project Template
====================================

Boilerplate project template for running a Flask-based application on
Google App Engine (Python)

Python 2.7 Runtime Support
--------------------------
* Support for the Python 2.7 runtime was added to this project in May 2012.


About Flask
-----------
[Flask][flask] is a BSD-licensed microframework for Python based on
[Werkzeug][wz], [Jinja2][jinja2] and good intentions.

See <http://flask.pocoo.org> for more info.


Setup/Configuration
-------------------
1. Download this repository via
   `git clone git@github.com:kamalgill/flask-appengine-template.git`
   or download the tarball at
   <http://github.com/kamalgill/flask-appengine-template/tarball/master>
2. Copy the src/ folder to your application's root folder
3. Set the application id in `src/app.yaml`
4. Configure datastore models at `src/application/models.py`
5. Configure application views at `src/application/views.py`
6. Configure URL routes at `src/application/urls.py`
7. Configure forms at `src/application/forms.py`
8. Add the secret keys for CSRF protection by running the `generate_keys.py`
   script at `src/application/generate_keys.py`, which will generate the
   secret keys module at src/application/secret_keys.py

Note: Copy the .gitignore file from the tarball folder's root to your git
repository root to keep the secret_keys module out of version control.

Or, add the following to your .(git|hg|bzr)ignore file

<pre class="console">
  # Keep secret keys out of version control
  secret_keys.py
</pre>


Install python dependencies
---------------------------
The local dev environment requires installation of Jinja2, PIL, and simplejson,
which can be installed via:

<pre class="console">
  pip install -r requirements_dev.txt
</pre>


Front-end Customization
-----------------------
1. Customize the main HTML template at
   `src/application/static/templates/base.html`
2. Customize CSS styles at `src/application/static/css/main.css`
3. Add custom JavaScript code at `src/application/static/js/main.js`
4. Customize favicon at `src/application/static/img/favicon.ico`
5. Customize 404 page at `src/application/templates/404.html`


Previewing the Application
--------------------------
To preview the application using App Engine's development server,
use [dev_appserver.py][devserver]

<pre class="console">
  dev_appserver.py src/
</pre>

Assuming the latest App Engine SDK is installed, the test environment is
available at <http://localhost:8080>


Admin Console
-------------
The admin console is viewable at http://localhost:8000 (note distinct port from dev app server)


Flask-Cache
-----------
The handy Flask-Cache extension is included, pre-configured for App Engine's Memcache API.
Use the "Flush Cache" button at http://localhost:8000/memcache to clear the cache.


Deploying the Application
-------------------------
To deploy the application to App Engine, use [appcfg.py update][appcfg]
<pre class="console">
  appcfg.py update src/
</pre>

The application should be visible at http://{YOURAPPID}.appspot.com


Folder structure
----------------
The App Engine app's root folder is located at `src/`.

<pre class="console">
  src/
  |-- app.yaml (App Engine config file)
  |-- application (application code)
  |-- index.yaml (App Engine query index definitions)
  |-- lib/
  |   |-- blinker/ (library for event/signal support)
  |   |-- flask/ (Flask core)
  |   |-- flask_cache/  (Flask-Cache extension)
  |   |-- flask_debugtoolbar/  (Port of Django Debug Toolbar to Flask)
  |   |-- flaskext/ (Flask extensions go here)
  |   |-- gae_mini_profiler/ (Appstats-based profiler)
  |   |-- itsdangerous.py (required by Flask >= 0.10
  |   |-- werkzeug/ (WSGI utilities for Python-based web development)
  |   `-- wtforms/ (Jinja2-compatible web form utility)
  |-- tests/ (unit tests)
</pre>

The application code is located at `src/application`.

<pre class="console">
  application/
  |-- __init__.py (initializes Flask app)
  |-- decorators.py (decorators for URL handlers)
  |-- forms.py (web form models and validators)
  |-- models.py (App Engine datastore models)
  |-- settings.py (settings for Flask app)
  |-- static
  | |-- css
  | | |-- bootstrap-*.css (Twitter Bootstrap styles)
  | | |-- fontawesome-*.css (Fontawesome styles)
  | | `-- main.css (custom styles)
  | |-- font
  | | `various fontawesome font files
  | |-- img
  | | |-- favicon.ico
  | | |-- favicon.png
  | | `-- glyphicons-*.png (Twitter bootstrap icons sprite)
  | `-- js
  |   |-- main.js (site-wide JS)
  |   `-- lib/ (third-party JS libraries)
  |     |--bootstrap-*.js (Bootstrap jQuery plugins
  |     `--modernizer-*.js (HTML5 detection library)
  |-- templates
  | |-- includes/ (common include files)
  | |-- 404.html (not found page)
  | |-- 500.html (server error page)
  | |-- base.html (master template)
  | |-- list_examples.html (example list-based template)
  | `-- new_example.html (example form-based template)
  |-- urls.py (URL dispatch routes)
  `-- views.py (Handlers for URL routes defined at urls.py)
</pre>


Removing Extended Attributes (@ flag)
-------------------------------------
A few of the files in the source tree were uploaded (with apologies) to
GitHub with extended attributes (notice the '@' symbol when running ls -al).

To remove the extended attributes, use `xattr -rd` at the root of the
src/ folder.

<pre class='console'>
  xattr -rd com.apple.quarantine .
  xattr -rd com.macromates.caret .
</pre>

Note: Windows users may safely ignore the xattr fix


Licenses
--------
See licenses/ folder


Package Versions
----------------
- Blinker: 1.1
- Bootstrap: 2.3.1
- Flask: 0.10
- Flask-Cache 0.10.1
- Flask-DebugToolbar: 0.7.1
- Flask-WTF: 0.6
- FontAwesome: 3.0
- itsdangerous: 0.22
- Jinja2: 2.6 (included in GAE)
- jQuery: 1.9.1 (set in base.html)
- Modernizr: 2.6.2
- Werkzeug: 0.8.3
- WTForms: 1.0.4


Credits
-------
Project template layout was heavily inspired by Francisco Souza's
[gaeseries Flask project][gaeseries]

Incorporates [Flask-DebugToolbar][debugtoolbar] by Matt Good et. al.
and [Flask-Cache][flaskcache] by Thadeus Burgess

Layout, form, table, and button styles provided by [Bootstrap][bootstrap]

[Font Awesome][fontawesome] by Dave Gandy

HTML5 detection provided by [Modernizr 2][modernizr] (configured with all features)


[appcfg]: http://code.google.com/appengine/docs/python/tools/uploadinganapp.html
[bootstrap]: http://twitter.github.com/bootstrap
[debugtoolbar]: https://readthedocs.org/projects/flask-debugtoolbar/
[devserver]: http://code.google.com/appengine/docs/python/tools/devserver.html
[flask]: http://flask.pocoo.org
[flaskcache]: http://pythonhosted.org/Flask-Cache/
[fontawesome]: http://fortawesome.github.com/Font-Awesome/
[html5]: http://html5boilerplate.com/
[jinja2]: http://jinja.pocoo.org/2/documentation/
[gaeseries]: http://github.com/franciscosouza/gaeseries/tree/flask
[modernizr]: http://www.modernizr.com/
[profiler]: http://packages.python.org/Flask-GAE-Mini-Profiler/
[wz]: http://werkzeug.pocoo.org/
[wzda]: https://github.com/nshah/werkzeug-debugger-appengine
