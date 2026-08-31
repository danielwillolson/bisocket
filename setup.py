from setuptools import setup, find_packages, Extension
from Cython.Build import cythonize

# List of Cython files to compile
extensions = [
    Extension("bisocket.cython.c_main", ["bisocket/cython/c_main.pyx"]),
]

# Requirements  for the package
with open('requirements.txt') as f:
    requirements = [
        line.strip() for line in
        f.read().splitlines()
        if line.strip() != '' and not line.strip().startswith('#')
    ]

# Read the long description from the README file
with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="bisocket",
    version="0.0.6",
    author="Daniel Olson",
    author_email="support@orphos.cloud",
    description="bisocket is a high-level Python library for simple, secure, and truly bidirectional socket communication, using a dual-socket architecture to enable non-blocking, full-duplex I/O. It provides automatic AES-GCM encryption and supports both synchronous (threading) and asynchronous (asyncio) client-server applications",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/danielwillolson/bisocket",
    packages=find_packages(),
    # package_name="terminal_query_search",
    metadata_version="2.3",  # Enforce an older version
    install_requires=requirements,
    # entry_points={
    #     'console_scripts': ['qq=query_search.cli:cli'],
    # },
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
    ],
    python_requires=">=3.10",
    keywords="socket bidirectional",
    # ext_modules=cythonize(extensions),
    package_data={
        'bisocket/cython': [
            "*.pyx", # This line ensures the .pyx files are installed with the final package
            "*.c",   # Include the generated C file as well
        ]
    },
    include_package_data=True,
)
