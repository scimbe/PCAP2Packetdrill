from setuptools import setup, find_packages

with open("README.md", "r", encoding="utf-8") as fh:
    long_description = fh.read()

setup(
    name="pcap2packetdrill",
    version="0.1.0",
    author="Martin Becke",
    author_email="Martin.Becke@HAW-Hamburg.de",
    description="Convert PCAP files to Packetdrill test scripts",
    long_description=long_description,
    long_description_content_type="text/markdown",
    url="https://github.com/scimbe/PCAP2Packetdrill",
    packages=find_packages(exclude=["tests", "examples"]),
    classifiers=[
        "Development Status :: 3 - Alpha",
        "Intended Audience :: Developers",
        "Intended Audience :: Telecommunications Industry",
        "License :: OSI Approved :: MIT License",
        "Programming Language :: Python :: 3",
        "Programming Language :: Python :: 3.8",
        "Programming Language :: Python :: 3.9",
        "Programming Language :: Python :: 3.10",
        "Programming Language :: Python :: 3.11",
        "Topic :: System :: Networking",
    ],
    python_requires=">=3.8",
    install_requires=[
        "scapy>=2.5.0",
        "click>=8.0.0",
        "jinja2>=3.0.0",
    ],
    extras_require={
        "dev": [
            "pytest>=7.0.0",
            "pytest-cov>=3.0.0",
            "black>=22.0.0",
            "isort>=5.10.0",
            "flake8>=4.0.0",
            "mypy>=0.950",
        ],
    },
    entry_points={
        "console_scripts": [
            "pcap2packetdrill=pcap2packetdrill.cli:main",
        ],
    },
    include_package_data=True,
    package_data={
        "pcap2packetdrill": ["templates/*.j2"],
    },
)
