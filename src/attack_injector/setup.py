import os
from glob import glob

from setuptools import find_packages, setup

package_name = 'attack_injector'

setup(
    name=package_name,
    version='0.1.0',
    packages=find_packages(exclude=['test']),
    data_files=[
        ('share/ament_index/resource_index/packages',
            ['resource/' + package_name]),
        ('share/' + package_name, ['package.xml']),
        (os.path.join('share', package_name, 'launch'), glob('launch/*.launch.py')),
    ],
    install_requires=['setuptools'],
    zip_safe=True,
    maintainer='nitin-nandakumar',
    maintainer_email='nitinnandakumar5237@gmail.com',
    description='Attack scenario injector for testing UAV security supervisor resilience.',
    license='Apache-2.0',
    tests_require=['pytest'],
    entry_points={
        'console_scripts': [
            'injector_node = attack_injector.injector_node:main',
        ],
    },
)
