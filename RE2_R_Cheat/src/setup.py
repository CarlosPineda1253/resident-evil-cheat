import setuptools
from distutils.core import setup
from Cython.Build import cythonize
from distutils.extension import Extension

extensions = [
    Extension('PYRE2_R_Cheat', ['PYRE2_R_Cheat.pyx', 'RE2_R_Cheat.cpp'],
              extra_compile_args=['-std=c++11'],
              language='c++'
              ),
]

setup(
    ext_modules=cythonize(extensions),
    # extra_compile_args=["-w", '-g'],
)