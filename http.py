import flask
from flask import request, escape
import json
from flask.json import JSONEncoder
import time
import logging
import jinja2
import base64, hashlib
import joblib

app = flask.Flask(__name__)




logging.basicConfig(filename="/var/log/secnotify/secnotify.log",
                    level=logging.DEBUG,
                    format='%(asctime)s:%(module)s:%(name)s:%(levelname)s:%(message)s')
logging.debug("secnotify startup")
logger = logging.getLogger()


def encode(ip_addr):
    split_addr = ip_addr.split(".")
    split_addr[0], split_addr[1] = split_addr[1], split_addr[0]
    split_addr[2], split_addr[3] = split_addr[3], split_addr[2]
    enc_a = base64.b64encode(str.encode(".".join(split_addr)))
    return enc_a


@app.after_request # CVE-2018-0285 Добавил филтрацию событий логера для исключения похещения данных внутренним нарушителем
def after_request(response):
    timestamp = time.strftime('[%Y-%b-%d %H:%M]')
    n_addr = encode(request.remote_addr)
    if (response.status == "200 OK"):
        app.logger.info(
                 '%s %s %s %s %s',
                            timestamp,
                                              n_addr,
                                              flask.request.method,
                                              flask.request.full_path,
                                              response.status                                               
                    )                
    else:          
        app.logger.error(
                      '%s %s %s %s %s',
                                               timestamp,
                                               n_addr,
                                               flask.request.method,
                                               flask.request.full_path,
                                               response.status                                               
                    )
    return response


@app.route('/feedback_form', methods=["GET", "POST"])
def introduction():
    feedback = ''
    with open('feedback.json', 'r') as feedback_file:
        feedback_dict = json.loads(feedback_file.read())
        for key, value in feedback_dict.items():
            feedback += "<p><i>Анононим, %s</i>: %s</p>" % (escape(key), escape(value)) #xss closed by escape
    return """<html>
                <title>Обратная связь</title>
                <body>
                %s
                    <form action="/save_feedback" method="post">
                        Поделитесь своим мнением: <input name="feedback" type="text" />
                        <input name="submit" type="submit" value="Отправить">
                    </form>
                </body>
            </html>
""" % feedback


@app.route('/save_feedback', methods=["GET", "POST"])
def index_page():
    feedback = flask.request.form.get('feedback')
    feedback_dict = {}
    with open('feedback.json', 'r') as feedback_file:
        feedback_dict.update(json.loads(feedback_file.read()))
    feedback_dict[time.time()] = feedback
    with open('feedback.json', 'w') as feedback_file:
        feedback_file.write(json.dumps(feedback_dict))
    return flask.redirect('/feedback_form')


@app.route('/secret', methods=["GET", "POST"]) # Закрыта уязвимость сериализоациии объекта pickle, т.к он является испольняемым 
def get_msg():
    if flask.request.method == 'POST':
        if flask.request.data:
            data=base64.b64decode(flask.request.data)
            new_str = data.decode('utf-8')
            msg = json.dumps(new_str)
            if joblib.hash(msg) == hashlib.sha256(msg.encode('utf8')).hexdigest():
                with open('messages', 'a') as msg_log:
                    msg_log.write(msg)               
    if flask.request.method == 'GET':
        f = open('messages', 'a')
        f.write("Error")
        f.close()
        return "NOPE"


@app.after_request
def add_header(response):
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    response.headers['Content-Security-Policy'] = "default-src 'self'" #nowadays not extersion
    return response

if __name__ == '__main__':
    app.run( )

