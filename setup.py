"""
Setup simples para instalar a lib desde a raiz
"""

from setuptools import find_packages, setup

setup(
    name="sunet",
    version="1.0.0",
    description="OpenID Federation ↔ OpenID Connect bridge for SATOSA.",
    url="https://github.com/GT-BAITA/satosa-federation",
    packages=find_packages(),
    install_requires=[
        "SATOSA",
        "gunicorn",
        "requests",
        "cryptography>=45.0.0",
        "pyOpenSSL>=23",
        "cryptojwt>=1.9",
        "pydantic>=2.0",
        "pem>=23.1",
        "aiohttp>=3.11",
        "pyeudiw[satosa] @ git+https://github.com/italia/eudi-wallet-it-python@c9d46cc61f0c77ecec21d43c72f49a85f462bc48",
    ],
    extras_require={
        "test": [
            "pytest",
            "pytest-cov",
            "flake8",
            "pytest-asyncio",
        ],
    },
    python_requires=">=3.10",
)
