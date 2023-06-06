from flask import Flask,render_template


helloapp = Flask(__name__)


@helloapp.route('/',methods=['GET'])
def index():
    frist_name='John'
    stuff= 'This is <strong> Bold </strong> Text'
    return render_template('index.html', 
                           frist_name=frist_name,
                           stuff=stuff)


# localhost:3700/user/danny
@helloapp.route('/user/<name>', methods=['GET'])
def user(name):
    return render_template('user.html', user_name=name)



#invalid url

@helloapp.errorhandler(404)
def page_not_found(e):
    return render_template("404.html"),404


@helloapp.errorhandler(500)
def page_not_found(e):
    return render_template("500.html"),500



if __name__ == "__main__":
    helloapp.run(port=3300,debug=True)


 