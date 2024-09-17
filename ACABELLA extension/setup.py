import pathlib
from setuptools import setup, find_packages

HERE = pathlib.Path(__file__).parent

VERSION = "0.1.0"
PACKAGE_NAME = "acabella"
AUTHOR = "Marloes Venema and Antonio de la Piedra"
AUTHOR_EMAIL = "marloes.venema@ru.nl and antonio@delapiedra.org"
URL = "https://github.com/abecryptools/acabella"

LICENSE = "GPL 3.0"
DESCRIPTION = "ACABELLA is a tool for analyzing the security of ABE schemes"
LONG_DESCRIPTION = (HERE / "README.md").read_text()
LONG_DESC_TYPE = "text/markdown"

INSTALL_REQUIRES = ["sympy"]

setup(
    name=PACKAGE_NAME,
    version=VERSION,
    description=DESCRIPTION,
    long_description=LONG_DESCRIPTION,
    long_description_content_type=LONG_DESC_TYPE,
    author=AUTHOR,
    license=LICENSE,
    author_email=AUTHOR_EMAIL,
    url=URL,
    install_requires=INSTALL_REQUIRES,
    packages=find_packages(where="src"),
    package_dir={"": "src"},
    entry_points={
        "console_scripts": [
            "acabella=acabella.cli:main",
        ],
    },
)
