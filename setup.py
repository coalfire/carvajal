import setuptools
import carvajal.__about__ as about

with open("README.rst", "r", encoding="utf-8") as fh:
    readme = fh.read()

setuptools.setup(
    name=about.__project__,
    version=about.__version__,
    author=about.__author__,
    author_email="noah.birnel@coalfire.com",
    description="Helper functions for describing AWS infrastructure",
    long_description=readme,
    long_description_content_type="text/x-rst",
    url="https://github.com/coalfire/carvajal",
    packages=setuptools.find_packages(),
    classifiers=[
        "Programming Language :: Python :: 3",
        "License :: OSI Approved :: MIT License",
        "Operating System :: OS Independent",
        "Development Status :: 3 - Alpha",
        "Environment :: Console",
        "Intended Audience :: System Administrators",
        "Intended Audience :: Information Technology",
        "Topic :: System :: Networking",
        "Topic :: Software Development :: Testing",
    ],
    python_requires=">=3.6",
    install_requires=[
        "boto3",
        "PyYaml",
        "pytest",
    ],
    setup_requires=[
        "wheel",
    ],
)
