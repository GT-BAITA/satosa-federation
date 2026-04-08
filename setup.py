"""
Setup simples para instalar a lib desde a raiz
"""

from setuptools import find_packages, setup

setup(
    name="sunet",
    version="1.0.0",
    description="OpenID Federation ↔ OpenID Connect bridge for SATOSA.",
    url="https://github.com/GT-BAITA/satosa-federation",
    packages=["sunet", "sunet.plugin"],
    package_dir={"sunet": "."},
    include_package_data=True,
    install_requires=[
        "requests>=2.0.0",
        "cryptography>=43.0.3",
        "pyopenssl>=24.2.1",
        "pydantic>=2.0",
        "pem>=23.1,<23.2",
        "aiohttp>=3.11.11,<4.0.0",
        "PyJWT>=2.0",
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
