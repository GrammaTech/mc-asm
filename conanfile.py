import os
import os.path

from conans import CMake, ConanFile


def read_version():
    fields = {}
    base_dir = os.environ.get("CI_PROJECT_DIR", None)
    if not base_dir or not os.path.isabs(base_dir):
        base_dir = os.path.dirname(__file__)
    with open(os.path.join(base_dir, "version.txt")) as f:
        for line in f:
            key, value = line.strip().split(" ")
            fields[key] = value
    return fields["VERSION_MAJOR"] + "." + fields["VERSION_MINOR"]


class MCAsmConan(ConanFile):
    name = "mcasm"
    version = read_version()
    author = "GrammaTech Inc."
    url = "https://git.grammatech.com/rewriting/mc-asm"
    description = "Assemble code to bytes using LLVM's MC layer"
    generators = "cmake"

    def source(self):
        project_dir = os.environ["CI_PROJECT_DIR"]
        self.run("git clone %s mcasm" % project_dir)

    def build(self):
        cmake = CMake(self)
        cmake.configure(
            source_folder="mcasm", defs={"CMAKE_VERBOSE_MAKEFILE:BOOL": "ON"}
        )
        cmake.build()
        cmake.test()
        cmake.install()

    def package(self):
        self.copy("*.h", dst="include", src="mcasm")
        self.copy("*mcasm.lib", dst="lib", keep_path=False)
        self.copy("*.dll", dst="bin", keep_path=False)
        self.copy("*.so", dst="lib", keep_path=False)
        self.copy("*.dylib", dst="lib", keep_path=False)
        self.copy("*.a", dst="lib", keep_path=False)

    def package_info(self):
        self.cpp_info.libs = ["mcasm"]
