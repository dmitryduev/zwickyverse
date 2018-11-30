from setuptools import setup

setup(name='zwickyverse', version='0.1.0', py_modules=['zwickyverse'],
      install_requires=['pymongo>=3.4.0',
                        'pytest>=3.3.0',
                        'requests>=2.18.4']
      )

