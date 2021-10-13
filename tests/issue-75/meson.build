e = environment()

openssl = dependency('openssl', required: false)
if openssl.found()
  issue75 = executable('issue75', 'issue-75.c',
                       dependencies: [libjose_dep, openssl])
  test('issue75', issue75, workdir : meson.current_source_dir(), env: e, timeout: 30)
endif
