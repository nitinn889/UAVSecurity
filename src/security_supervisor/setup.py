from setuptools import find_packages, setup

package_name = 'security_supervisor'

setup(
    name=package_name,
    version='0.1.0',
    packages=find_packages(exclude=['test']),
    data_files=[
        ('share/ament_index/resource_index/packages',
            ['resource/' + package_name]),
        ('share/' + package_name, ['package.xml']),
    ],
    install_requires=['setuptools'],
    zip_safe=True,
    maintainer='nitin-nandakumar',
    maintainer_email='nitinnandakumar5237@gmail.com',
    description='Onboard security supervisor: sensor monitoring, trust scoring, anomaly detection, and autonomous response for UAVs.',
    license='Apache-2.0',
    tests_require=['pytest'],
    entry_points={
        'console_scripts': [
            'sensor_monitor = security_supervisor.sensor_monitor:main',
            'actuator = security_supervisor.actuator_node:main',
            'data_logger = security_supervisor.data_logger:main',
            'response_engine = security_supervisor.response_engine:main',
            'supervisor = security_supervisor.supervisor_node:main',
            'supervisor_node = security_supervisor.supervisor_node:main',
        ],
    },
)
