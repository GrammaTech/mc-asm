import sys

from setuptools import find_namespace_packages

try:
    from skbuild import setup
except ImportError:
    print(
        "Please update pip, you need pip 10 or greater, or you need to install"
        " the PEP 518 requirements in pyproject.toml yourself",
        file=sys.stderr,
    )
    raise

version = {}
with open("src/mcasm/version.py") as fp:
    exec(fp.read(), version)

with open("README.md", "r") as f:
    long_description = f.read()

setup(
    name="mcasm",
    author="GrammaTech, Inc.",
    author_email="gtirb@grammatech.com",
    version=version["__version__"],
    description="Assemble code to bytes using LLVM's MC layer",
    classifiers=[
        "Intended Audience :: Developers",
        "Programming Language :: Python :: 3",
    ],
    python_requires=">=3.6",
    install_requires=[],
    dependency_links=[],
    license="MIT",
    packages=find_namespace_packages(where="src"),
    package_dir={"": "src"},
    cmake_install_dir="src/mcasm",
    include_package_data=True,
    extras_require={"test": ["pytest"], "cli": ["rich~=12.0"]},
    long_description=long_description,
    package_data={
        "mcasm": ["py.typed", "_core/__init__.pyi", "_core/mc/__init__.pyi"]
    },
    long_description_content_type="text/markdown",
    url="https://github.com/grammatech/mc-asm",
)
