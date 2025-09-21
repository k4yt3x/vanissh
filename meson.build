project(
  'vanissh',
  'cpp',
  version: '1.0.0',
  meson_version: '>1.1',
  default_options: ['cpp_std=c++23'],
)

# Options
native_opt = get_option('enable_native')
fast_math_opt = get_option('enable_fast_math')

# Find dependencies
openssl_dep = dependency('openssl', required: true)
threads_dep = dependency('threads', required: true)
libssh_dep = dependency('libssh', required: true)

# Source files
sources = ['src/main.cpp', 'src/base64_encoder.cpp', 'src/ssh_key_generator.cpp']

# Compiler arguments
cpp_args = []
link_args = []

# Compiler-specific flags
cpp = meson.get_compiler('cpp')
if cpp.get_id() == 'gcc' or cpp.get_id() == 'clang'
  cpp_args += ['-Wall', '-Wextra', '-Wpedantic', '-Wconversion', '-Wshadow']
  link_args += ['-flto', '-Wl,--strip-all']

  if native_opt
    cpp_args += ['-march=native']
  endif

  if fast_math_opt
    cpp_args += ['-O3', '-ffast-math']
  endif
endif

# Create executable
executable(
  'vanissh',
  sources,
  dependencies: [openssl_dep, threads_dep, libssh_dep],
  cpp_args: cpp_args,
  link_args: link_args,
  include_directories: 'src',
  install: true,
)
