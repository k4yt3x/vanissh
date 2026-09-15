project(
  'vanissh',
  'cpp',
  version: '2.1.0',
  meson_version: '>=1.1',
  default_options: ['cpp_std=c++23', 'cuda_std=c++17', 'b_lto=true'],
)

# Options
native_opt = get_option('enable_native')
cuda_opt = get_option('enable_cuda')

# Find dependencies
openssl_dep = dependency('openssl', required: true)
threads_dep = dependency('threads', required: true)

# Source files
sources = ['src/main.cpp', 'src/base64_encoder.cpp', 'src/ssh_key_generator.cpp']
deps = [openssl_dep, threads_dep]
link_with = []

# Compiler arguments
cpp_args = ['-DVANISSH_VERSION="' + meson.project_version() + '"']
link_args = []

# Compiler-specific flags
cpp = meson.get_compiler('cpp')
if cpp.get_id() == 'gcc' or cpp.get_id() == 'clang'
  cpp_args += ['-Wall', '-Wextra', '-Wpedantic', '-Wconversion', '-Wshadow']

  if native_opt
    cpp_args += ['-march=native']
  endif

  if get_option('buildtype') == 'release'
    link_args += ['-Wl,--strip-all']
  endif
endif

# Optional CUDA backend
have_cuda = add_languages('cuda', native: false, required: cuda_opt)
if have_cuda
  # The static CUDA runtime is located relative to nvcc rather than through
  # dependency('cuda'): that only searches CUDA_PATH and /usr/local/cuda, and in
  # NVIDIA's container images its library probing is misled by LIBRARY_PATH
  # pointing at the driver stubs.
  fs = import('fs')
  cuda_root = fs.parent(fs.parent(find_program('nvcc').full_path()))
  cudart_static = cpp.find_library(
    'cudart_static',
    dirs: [cuda_root / 'lib64', cuda_root / 'targets' / 'x86_64-linux' / 'lib'],
  )
  cuda_dep = declare_dependency(
    dependencies: [cudart_static, cpp.find_library('dl'), cpp.find_library('rt'), threads_dep],
  )

  cuda_args = [
    '-O3',
    '-arch=' + get_option('gpu_arch'),
    '-DVANISSH_CUDA_WINDOW=' + get_option('gpu_window').to_string(),
  ]

  # Built as a separate static library so the executable is still linked by the C++ compiler
  vanissh_cuda = static_library(
    'vanissh_cuda',
    'src/cuda/cuda_backend.cu',
    cuda_args: cuda_args,
    include_directories: 'src',
  )

  sources += ['src/cuda/cuda_vanity_generator.cpp']
  cpp_args += ['-DVANISSH_CUDA']
  deps += [cuda_dep]
  link_with += [vanissh_cuda]
endif

# Create executable
vanissh = executable(
  'vanissh',
  sources,
  dependencies: deps,
  link_with: link_with,
  link_language: 'cpp',
  cpp_args: cpp_args,
  link_args: link_args,
  include_directories: 'src',
  install: true,
)

# Tests
smoke_test = find_program('tests/smoke_test.sh')
test('smoke test (cpu)', smoke_test, args: [vanissh, '-j', '2'], timeout: 120)

# Encodings and the CPU matcher against an independent reference
matcher_test = executable(
  'matcher_test',
  ['tests/matcher_test.cpp', 'src/base64_encoder.cpp', 'src/ssh_key_generator.cpp'],
  dependencies: [openssl_dep, threads_dep],
  cpp_args: cpp_args,
  include_directories: ['src', 'tests'],
)
test('matcher unit tests', matcher_test, timeout: 120)

# Every combination of target, pattern kind and case mode, end to end; takes
# minutes, so the default test setup below skips the 'extended' suite
matrix_test = find_program('tests/matrix_test.sh')
test('matrix (cpu)', matrix_test, args: [vanissh], timeout: 1800, suite: 'extended')
if have_cuda
  test('smoke test (gpu)', smoke_test, args: [vanissh, '-g'], timeout: 120)
  test('matrix (gpu)', matrix_test, args: [vanissh, '-g'], timeout: 1800, suite: 'extended')

  # Device arithmetic against OpenSSL BIGNUM and Ed25519
  ed25519_test = executable(
    'ed25519_test',
    'tests/ed25519_test.cu',
    dependencies: [cuda_dep, openssl_dep],
    cuda_args: cuda_args,
    link_language: 'cpp',
    include_directories: ['src', 'tests'],
  )
  test('ed25519 unit tests', ed25519_test, timeout: 300)
endif

# `meson test` skips the extended suite; run it with
# `meson test --setup full --suite extended`
add_test_setup('quick', exclude_suites: ['extended'], is_default: true)
add_test_setup('full')
