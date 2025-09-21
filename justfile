bindir := "build"

build:
    CXX=clang++ meson setup '{{bindir}}' --reconfigure \
        --buildtype=release \
        -Denable_native=true \
        -Denable_fast_math=true
    meson compile -C '{{bindir}}'

debug:
    CXX=clang++ meson setup '{{bindir}}' --reconfigure \
        --buildtype=debug \
        -Denable_native=false \
        -Denable_fast_math=false
    meson compile -C '{{bindir}}'

clean:
    rm -rf '{{bindir}}'
