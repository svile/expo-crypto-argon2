require 'json'

package = JSON.parse(File.read(File.join(__dir__, 'package.json')))

Pod::Spec.new do |s|
  s.name           = 'ExpoCryptoArgon2'
  s.version        = package['version']
  s.summary        = package['description']
  s.license        = { type: package['license'] }
  s.homepage       = 'https://github.com/inntend/expo-crypto-argon2'
  s.authors        = 'expo-crypto-argon2 contributors'
  s.platform       = :ios, '13.4'
  s.swift_version  = '5.4'
  # Source is set by the consuming app (local path or git URL)
  s.source         = { git: '' }

  s.dependency 'ExpoModulesCore'

  # Swift module + ObjC++ C bridge + phc-winner-argon2 C sources
  # Exclude src/run.c — it defines its own main() (CLI entry point)
  s.source_files = [
    'ios/**/*.{h,m,mm,swift}',
    'c-argon2/include/argon2.h',
    'c-argon2/src/argon2.c',
    'c-argon2/src/core.c',
    'c-argon2/src/encoding.c',
    'c-argon2/src/ref.c',
    'c-argon2/src/thread.c',
    'c-argon2/src/blake2/blake2b.c',
  ]

  # Make argon2.h findable via #include "argon2.h" in Argon2Wrapper.mm
  # pod_target_xcconfig applies only to this pod, not to the consumer
  s.pod_target_xcconfig = {
    'HEADER_SEARCH_PATHS' => '"${PODS_TARGET_SRCROOT}/c-argon2/include"',
    'CLANG_CXX_LANGUAGE_STANDARD' => 'c++17',
  }
end
