bindir := "build"

build:
    CXX=clang++ meson setup '{{bindir}}' --reconfigure \
        --buildtype=release \
        -Denable_native=true \
        -Denable_cuda=auto
    meson compile -C '{{bindir}}'

build-cpu:
    CXX=clang++ meson setup '{{bindir}}' --reconfigure \
        --buildtype=release \
        -Denable_native=true \
        -Denable_cuda=disabled
    meson compile -C '{{bindir}}'

debug:
    CXX=clang++ meson setup '{{bindir}}' --reconfigure \
        --buildtype=debug \
        -Denable_native=false \
        -Denable_cuda=auto \
        -Db_lto=false
    meson compile -C '{{bindir}}'

test:
    meson test -C '{{bindir}}' --print-errorlogs

format:
    clang-format -i src/*.cpp src/*.h src/cuda/*.cpp src/cuda/*.h src/cuda/*.cu src/cuda/*.cuh tests/*.cu

clean:
    rm -rf '{{bindir}}'
