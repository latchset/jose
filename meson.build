project('jose', 'c', license: 'APL2',
  version: '11',
  default_options: [
    'c_std=gnu99',
    'prefix=/usr',
    'warning_level=2',
    'werror=true'
  ]
)

licensedir = join_paths(get_option('prefix'), 'share', 'licenses', meson.project_name())
if build_machine.system() == 'freebsd'
  licensedir += '-'+meson.project_version()
endif

add_project_arguments(
  '-I' + meson.current_source_dir(),
  '-I' + meson.current_build_dir(),
  '-Wstrict-aliasing',
  '-Wchar-subscripts',
  '-Wformat-security',
  '-Wmissing-declarations',
  '-Wmissing-prototypes',
  '-Wnested-externs',
  '-Wpointer-arith',
  '-Wshadow',
  '-Wsign-compare',
  '-Wstrict-prototypes',
  '-Wtype-limits',
  '-Wunused-function',
  '-Wno-missing-field-initializers',
  '-Wno-unused-command-line-argument',
  '-Wno-unused-parameter',
  '-Wno-unknown-pragmas',
  language: 'c'
)

zlib = dependency('zlib')
threads = dependency('threads')
jansson = dependency('jansson', version: '>=2.10')
libcrypto = dependency('libcrypto', version: '>=1.0.2')
a2x = find_program('a2x', required: false)

mans = []

licenses = ['COPYING']

subdir('jose')
subdir('doc')
subdir('lib')
subdir('cmd')
subdir('tests')

install_data(licenses, install_dir: licensedir)

pkg = import('pkgconfig')
pkg.generate(
  description: 'Library for managing JOSE objects',
  version: meson.project_version(),
  filebase: meson.project_name(),
  name: 'José Library',

  requires_private: [ 'zlib', 'libcrypto' ],
  libraries: libjose,
  requires: 'jansson',
)

if a2x.found()
  foreach m : mans
    custom_target(m.split('/')[-1], input: m + '.adoc', output: m.split('/')[-1],
      command: [a2x, '-f', 'manpage', '-D', meson.current_build_dir(), '@INPUT@'],
      install_dir: join_paths(get_option('mandir'), 'man' + m.split('.')[-1]),
      install: true
    )
  endforeach
else
  warning('Will not build man pages due to missing dependencies!')
endif
