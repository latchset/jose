flags = []
code = 'int main() { return 0; }'
cc = meson.get_compiler('c')

# Handle symbol visibility per platform
if build_machine.system() == 'darwin'
  # macOS: Skip symbol visibility restrictions for now
  # macOS linker doesn't support the same flags as GNU ld
  flags = []
elif build_machine.system() == 'freebsd'
  version_script_flags = '-Wl,--version-script=' + meson.current_source_dir() + '/libjose.map'
  if not cc.links(code, args: version_script_flags + ',--undefined-version' , name: '-Wl,--version-script=...')
     flags = [ '-export-symbols-regex=^jose_.*' ]
  else
     flags = [version_script_flags]
  endif
else
  # Linux and other systems
  version_script_flags = '-Wl,--version-script=' + meson.current_source_dir() + '/libjose.map'
  if not cc.links(code, args: version_script_flags, name: '-Wl,--version-script=...')
     flags = [ '-export-symbols-regex=^jose_.*' ]
  else
     flags = [version_script_flags]
  endif
endif

libjose_lib = shared_library('jose',
  'misc.c',           'misc.h',
  'cfg.c',
  'io.c',
  'b64.c',
  'hsh.c',            'hsh.h',
  'hooks.c',          'hooks.h',
  'jwk.c',
  'jws.c',
  'jwe.c',
  'zlib/deflate.c',
  'openssl/aescbch.c',
  'openssl/aesgcm.c',
  'openssl/aesgcmkw.c',
  'openssl/aeskw.c',
  'openssl/compat.c', 'openssl/compat.h',
  'openssl/dir.c',
  'openssl/ec.c',
  'openssl/ecdh.c',
  'openssl/ecdhes.c',
  'openssl/ecmr.c',
  'openssl/ecdsa.c',
  'openssl/hash.c',
  'openssl/hmac.c',
  'openssl/jwk.c',
  'openssl/lock.c',
  'openssl/misc.c',   'openssl/misc.h',
  'openssl/oct.c',
  'openssl/pbes2.c',
  'openssl/rsa.c',
  'openssl/rsaes.c',
  'openssl/rsassa.c',

  include_directories: incdir,
  dependencies: [zlib, jansson, libcrypto, threads],
  version: '0.0.0',
  link_args: flags,
  install: true
)

libjose_dep = declare_dependency(
  include_directories: incdir,
  dependencies: jansson,
  link_with: libjose_lib
)
