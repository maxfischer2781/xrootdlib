#!/usr/bin/env python
import os
from setuptools import setup, find_packages

repo_base_dir = os.path.abspath(os.path.dirname(__file__))
# pull in the packages metadata
package_about = {}
with open(os.path.join(repo_base_dir, "xrootdlib", "__about__.py")) as about_file:
    exec(about_file.read(), package_about)


if __name__ == '__main__':
    setup(
        name=package_about['__title__'],
        version=package_about['__version__'],
        description=package_about['__summary__'],
        long_description=package_about['__doc__'],
        author=package_about['__author__'],
        author_email=package_about['__email__'],
        url=package_about['__url__'],
        packages=find_packages(),
        zip_safe=True,
        # dependencies
        install_requires=['chainlet'],
        extras_require={
            'docs': ['sphinx'],
        },
        # metadata for package seach
        license='MIT',
        classifiers=[
            'Development Status :: 4 - Beta',
            'Intended Audience :: Developers',
            'Intended Audience :: System Administrators',
            'License :: OSI Approved :: MIT License',
            'Topic :: System :: Monitoring',
            'Programming Language :: Python :: 3',
            'Programming Language :: Python :: 3.3',
            'Programming Language :: Python :: 3.4',
            'Programming Language :: Python :: 3.5',
            'Programming Language :: Python :: 3.6',
        ],
        keywords='xrootd tools monitoring streams',
        # unit tests
        # test_suite='chainlet_unittests',
        # use unittest backport to have subTest etc.
        # tests_require=['unittest2'] if sys.version_info < (3, 4) else [],
    )
