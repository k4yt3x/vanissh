project(
  'vanissh',
  'cpp',
  version: '2.0.0',
  meson_version: '>=1.1',
  default_options: ['cpp_std=c++23', 'cuda_std=c++17', 'b_lto=true'],
)

# Options
native_opt = get_option('enable_native')
cuda_opt = get_option('enable_cuda')

# Find dependencies
openssl_dep = dependency('openssl', required: true)
threads_dep = dependency('threads', required: true)
libssh_dep = dependency('libssh', required: true)

# Source files
sources = ['src/main.cpp', 'src/base64_encoder.cpp', 'src/ssh_key_generator.cpp']
deps = [openssl_dep, threads_dep, libssh_dep]
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
  cuda_dep = dependency('cuda', version: '>=12.0', modules: ['cudart_static'], required: false)
  if not cuda_dep.found()
    # Meson only searches CUDA_PATH and /usr/local/cuda; derive the toolkit root from nvcc
    fs = import('fs')
    cuda_root = fs.parent(fs.parent(find_program('nvcc').full_path()))
    cuda_dep = declare_dependency(
      dependencies: [
        cpp.find_library('cudart_static', dirs: cuda_root / 'lib64'),
        cpp.find_library('dl'),
        cpp.find_library('rt'),
        threads_dep,
      ],
    )
  endif

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
if have_cuda
  test('smoke test (gpu)', smoke_test, args: [vanissh, '-g'], timeout: 120)
endif
