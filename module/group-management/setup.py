from setuptools import find_packages, setup

setup(
    name='group-management',
    version='0.1',
    author='Your Name',
    author_email='your.email@example.com',
    description='A group management application',
    packages=find_packages(),
    install_requires=[
        ''
    ],
    entry_points={
        'app.modules': [
            'group-management = group_management',
        ]
    },
)