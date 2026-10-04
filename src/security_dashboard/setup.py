from setuptools import find_packages, setup

package_name = 'security_dashboard'

setup(
    name=package_name,
    version='0.1.0',
    packages=find_packages(exclude=['test']),
    data_files=[
        ('share/ament_index/resource_index/packages',
            ['resource/' + package_name]),
        ('share/' + package_name, ['package.xml']),
    ],
    # The Flask app resolves its static dir relative to web_server.py, so the
    # UI must be installed next to the module rather than into share/.
    package_data={package_name: ['static/*']},
    install_requires=['setuptools', 'flask'],
    zip_safe=False,
    maintainer='nitin-nandakumar',
    maintainer_email='nitinnandakumar5237@gmail.com',
    description='Operator-facing dashboard for UAV security supervisor status and events.',
    license='Apache-2.0',
    tests_require=['pytest'],
    entry_points={
        'console_scripts': [
            'dashboard_node = security_dashboard.dashboard_node:main',
            'dashboard = security_dashboard.dashboard_node:main',
        ],
    },
)
