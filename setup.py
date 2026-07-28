import os

from setuptools import find_packages, setup

here = os.path.abspath(os.path.dirname(__file__))
meta = {}
with open(os.path.join(here, "jerryproxy", "config", "meta.py"), "r", encoding="utf-8") as stream:
    exec(stream.read(), meta)


def load_requirements(filename):
    with open(os.path.join(here, filename), "r", encoding="utf-8") as stream:
        return [line.strip() for line in stream if line.strip() and not line.startswith("#")]


with open(os.path.join(here, "README.md"), "r", encoding="utf-8") as stream:
    readme = stream.read()


setup(
    name="jerryproxy",
    version=meta["__VERSION__"],
    description=meta["__DESCRIPTION__"],
    long_description=readme,
    long_description_content_type="text/markdown",
    author=meta["__AUTHOR__"],
    author_email=meta["__AUTHOR_EMAIL__"],
    url="https://github.com/narugo1992/jerryproxy",
    license="Apache-2.0",
    python_requires=">=3.7",
    packages=find_packages(include=("jerryproxy", "jerryproxy.*")),
    package_data={"jerryproxy.data": ["*.json"]},
    include_package_data=True,
    install_requires=load_requirements("requirements.txt"),
    extras_require={
        "test": load_requirements("requirements-test.txt"),
        "dev": load_requirements("requirements-dev.txt"),
        "doc": load_requirements("requirements-doc.txt"),
    },
    entry_points={"console_scripts": ["jerryproxy=jerryproxy.cli:main"]},
    classifiers=[
        "Development Status :: 2 - Pre-Alpha",
        "Environment :: Console",
        "Intended Audience :: End Users/Desktop",
        "Intended Audience :: System Administrators",
        "License :: OSI Approved :: Apache Software License",
        "Operating System :: OS Independent",
        "Operating System :: Microsoft :: Windows",
        "Operating System :: MacOS",
        "Operating System :: POSIX :: Linux",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3 :: Only",
        "Programming Language :: Python :: 3.7",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
        "Topic :: Internet :: Proxy Servers",
        "Topic :: System :: Installation/Setup",
        "Topic :: Utilities",
    ],
    project_urls={
        "Source": "https://github.com/narugo1992/jerryproxy",
        "Issues": "https://github.com/narugo1992/jerryproxy/issues",
        "Documentation": "https://jerryproxy.readthedocs.io/",
    },
)
