cd = configuration_data()
cd.set('VERSION', meson.project_version())
configure_file(
  input: 'jose.h.in',
  output: 'jose.h',
  configuration: cd
)

install_headers(
  meson.current_build_dir() + '/jose.h',
  'cfg.h',
  'io.h',
  'b64.h',
  'jwk.h',
  'jws.h',
  'jwe.h',
  'openssl.h',
  subdir: meson.project_name()
)
