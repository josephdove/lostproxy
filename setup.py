from setuptools import setup, find_packages
from pathlib import Path

setup(
	name='lostproxy',
	version='0.1.2',
	author='Joseph',
	author_email='josephdove@proton.me',
	description='A multifunctional python proxy',
    long_description=(Path(__file__).parent / "README.md").read_text(),
    long_description_content_type='text/markdown',
	classifiers=[
		'Programming Language :: Python :: 3.10',
		'License :: OSI Approved :: MIT License',
		'Operating System :: OS Independent',
	],
    packages=find_packages(
        include=[
            "lostproxy",
            "lostproxy.*",
        ]
    ),
	entry_points={
		"console_scripts": [
			"lostproxy = lostproxy.lostproxy:run",
		]
	},
	python_requires='>=3.6',
)