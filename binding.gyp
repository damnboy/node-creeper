{
  'targets': [
    {
      'target_name': 'node-creeper-native',
      'sources': [ 
        'src/node_creeper.cc',
        'src/scanner.cc',
        "src/packet.cc",
        "src/device.cc",
        "src/capture.cc"
        ],
      'variables': {
        'static_pcap_lib%':"<!@(node -p 'process.cwd()')" + '/src/libpcap',
       },
      'include_dirs': [
        "<!@(node -p \"require('node-addon-api').include\")",
        "src/libpcap/"
        ],
        'libraries' : [
          '-L<@(static_pcap_lib)',
          '-lpcap',
          '-lcrypto'

        ],
      'dependencies': ["<!(node -p \"require('node-addon-api').gyp\")"],
      'cflags!': [ '-fno-exceptions' ],
      'cflags_cc!': [ '-fno-exceptions' ],
      'conditions': [
        ['OS == "linux"',{
          'defines': [
             'HAVE_SYS_IOCTL_H = 1',
             'HAVE_NET_BPF_H = 0'
          ],
        }],
        ['OS == "mac"',{
          'defines': [
             'HAVE_SYS_IOCTL_H = 1',
             'HAVE_NET_BPF_H = 1',
          ],
          'xcode_settings': {
            'GCC_ENABLE_CPP_EXCEPTIONS': 'YES',
            'CLANG_CXX_LIBRARY': 'libc++',
            'MACOSX_DEPLOYMENT_TARGET': '10.11'
          }
        }]
      ],
    }
  ]
}