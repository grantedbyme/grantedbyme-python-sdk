from setuptools import setup

setup(name='grantedbyme',
      version='1.0.8',
      description='Instant secure login without password',
      url='https://github.com/grantedbyme/grantedbyme-python-sdk',
      author='GrantedByMe',
      author_email='info@grantedby.me',
      license='MIT',
      packages=['grantedbyme'],
      zip_safe=False,
      install_requires=[
          'cryptography',
          'pyopenssl',
          'simplejson',
          'requests'
      ])
