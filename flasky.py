import os
import sys
import click
from flask_migrate import Migrate
from app import create_app, db
from app.models import User, Role

app = create_app(os.getenv('FLASK_CONFIG') or 'default')


@app.shell_context_processor
def make_shell_context():
    return dict(db=db, User=User, Role=Role)

@app.cli.command()
def test():
    """Run the unit tests."""
    import unittest
    tests = unittest.TestLoader().discover('tests')
    unittest.TextTestRunner(verbosity=2).run(tests)
# 在请求分析器的监视下运行应用
@app.cli.command()
@click.option('--length', default=25,

              help='Number of functions to include in the profiler report.')

@click.option('--profile-dir', default=None,
              help='Directory where profiler data files are saved.')
def profile(length, profile_dir):

    """Start the application under the code profiler."""

    from werkzeug.contrib.profiler import ProfilerMiddleware

    app.wsgi_app = ProfilerMiddleware(app.wsgi_app, restrictions=[length],

                                      profile_dir=profile_dir)

    app.run(debug=False)

if __name__ == "__main__":

    app.run(debug=True)