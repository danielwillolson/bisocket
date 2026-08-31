import os

from setuptools import setup, find_packages, Extension
from setuptools.command.build_ext import build_ext

VERSION = "0.0.8"

# bisocket/cython/c_main.pyx is generated from bisocket/main.py by build_helper.py,
# so the two can never drift apart. The extension is an optional speed-up: if
# Cython or a C compiler is missing, the install still succeeds and bisocket
# falls back to the pure-Python bisocket/main.py.
CYTHON_SOURCE = os.path.join("bisocket", "cython", "c_main.pyx")

ext_modules = []
try:
    from Cython.Build import cythonize
except ImportError:
    print("NOTE: Cython not available; building bisocket as pure Python.")
else:
    if os.path.exists(CYTHON_SOURCE):
        ext_modules = cythonize(
            [Extension("bisocket.cython.c_main", [CYTHON_SOURCE])],
            # force=True stops Cython from reusing a c_main.c that happens to be
            # newer than the .pyx, which silently ships the previous release's code.
            force=True,
            language_level="3",
            compiler_directives={"language_level": "3"},
        )


class OptionalBuildExt(build_ext):
    """Build the extension if we can, but never fail the install over it."""

    def run(self):
        try:
            super().run()
        except Exception as e:
            print(f"WARNING: C extension build failed, using pure Python instead: {e}")

    def build_extension(self, ext):
        try:
            super().build_extension(ext)
        except Exception as e:
            print(f"WARNING: could not build {ext.name}, using pure Python instead: {e}")


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
    version=VERSION,
    author="Daniel Olson",
    author_email="support@orphos.cloud",
    description="bisocket is a high-level Python library for simple, secure, and truly bidirectional socket communication, using a dual-socket architecture to enable non-blocking, full-duplex I/O. It provides automatic AES-GCM encryption and supports both synchronous (threading) and asynchronous (asyncio) client-server applications",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/danielwillolson/bisocket",
    packages=find_packages(),
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
        "Programming Language :: Python :: 3.13",
        "Topic :: System :: Networking",
    ],
    python_requires=">=3.10",
    keywords="socket bidirectional",
    ext_modules=ext_modules,
    cmdclass={"build_ext": OptionalBuildExt},
    # Keys are package names, not paths, and only ship the .pyx: a generated
    # .c in the wheel is what goes stale between releases.
    package_data={
        'bisocket.cython': ["*.pyx"],
    },
    include_package_data=True,
    zip_safe=False,
)
