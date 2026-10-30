import pathlib
import re

from setuptools import find_packages, setup

# FileNotFoundError is not there in Python 2, define it:
try:
    FileNotFoundError
except NameError:
    FileNotFoundError = IOError

here = pathlib.Path(__file__).parent

# Extract version from gixy/__init__.py
with open(here / "gixy" / "__init__.py", "r", encoding="utf-8") as fd:
    version = re.search(
        r'^version\s*=\s*[\'"]([^\'"]*)[\'"]',
        fd.read(),
        re.MULTILINE,
    ).group(1)

if not version:
    raise RuntimeError("Cannot find version information")

install_requires = [
    "crossplane>=0.5.8",
    "Jinja2>=2.8",
    "ConfigArgParse>=0.11.0",
    "tldextract>=5.3.0",
]

tests_requires = [
    "pytest>=7.0.0",
    "pytest-xdist",
]

dev_requires = tests_requires + [
    "coverage>=4.3",
    "flake8>=3.2",
    "tox>=2.7.0",
    "setuptools",
    "twine",
]

long_description = None
readme_path = here / "README.md"
docs_index_path = here / "docs" / "en" / "index.md"

try:
    text = readme_path.read_text(encoding="utf-8")
    single_line = text.strip()
    if single_line.endswith(".md") and "\n" not in single_line:
        candidate = here / single_line
        try:
            long_description = candidate.read_text(encoding="utf-8")
        except FileNotFoundError:
            long_description = text
    else:
        long_description = text
except FileNotFoundError:
    try:
        long_description = docs_index_path.read_text(encoding="utf-8")
    except FileNotFoundError:
        long_description = None

setup(
    name="Gixy-Next",
    version=version,

    description=(
        "Open source NGINX configuration security scanner for "
        "detecting nginx security/performance misconfigurations"
    ),

    long_description=long_description,
    long_description_content_type="text/markdown",

    keywords=[
        "nginx",
        "nginx security",
        "nginx hardening",
        "nginx configuration",
        "nginx config",
        "nginx config scanner",
        "nginx configuration checker",
        "nginx config linter",
        "nginx security scanner",
        "nginx configuration static analyzer",
        "nginx vulnerability scanner",
        "nginx.conf security audit",
        "configuration compliance",
        "configuration security",
        "static analysis",
        "ssrf",
        "http response splitting",
        "host header spoofing",
        "version disclosure",
        "redos",
        "gixy",
        "gixy next",
        "gixy-ng",
        "gixyng",
    ],

    author="Joshua Rogers",
    author_email="gixy@joshua.hu",

    url="https://gixy.io/",
    project_urls={
        "Homepage": "https://gixy.io/",
        "Documentation": "https://gixy.io/",
        "Source": "https://github.com/MegaManSec/gixy-next",
        "Issue Tracker": "https://github.com/MegaManSec/gixy-next/issues",
        "Original Gixy": "https://github.com/yandex/gixy",
    },

    packages=find_packages(exclude=["tests", "tests.*"]),
    include_package_data=True,

    install_requires=install_requires,
    extras_require={
        "tests": tests_requires,
        "dev": dev_requires,
        # Optional: ReDoS checks via external API
        "redos": ["requests>=2.20.0"],
    },

    entry_points={
        "console_scripts": [
            "gixy=gixy.cli.main:main",
            "gixy-next=gixy.cli.main:main",
        ],
    },

    license="MPL-2.0",

    license_files=["LICENSE"],

    classifiers=[
        "Environment :: Console",

        "Intended Audience :: System Administrators",
        "Intended Audience :: Developers",
        "Intended Audience :: Information Technology",

        "Topic :: Security",
        "Topic :: System :: Systems Administration",
        "Topic :: Internet :: WWW/HTTP :: Site Management",
        "Topic :: Software Development :: Quality Assurance",
        "Topic :: Software Development :: Testing",
        "Topic :: Utilities",

        "Operating System :: POSIX :: Linux",

        "Programming Language :: Python",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.11",
        "Programming Language :: Python :: 3.12",
        "Programming Language :: Python :: 3.13",
        "Programming Language :: Python :: 3.14",
        "Programming Language :: Python :: 3.15",
    ],

    python_requires=">=3.11",
)
