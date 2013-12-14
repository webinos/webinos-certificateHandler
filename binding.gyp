{
  'targets': 
  [
    {
       # Needed declarations for the target
      'target_name': 'certificate_manager',
      'product_name': 'certificate_manager',
        'sources': [ #Specify your source files here
          'src/certificate_manager.cpp',
          'src/openssl_wrapper.cpp',
        ],
      
      'conditions': [
        [ 'OS=="win"', {
		  'conditions': [
		    # "openssl_root" is the directory on Windows of the OpenSSL files.
		    # Check the "target_arch" variable to set good default values for
		    # both 64-bit and 32-bit builds of the module.
		    ['target_arch=="x64"', {
			  'variables': {
			    'openssl_root%': 'C:/OpenSSL-Win64'
			  },
		    }, {
			  'variables': {
			    'openssl_root%': 'C:/OpenSSL-Win32'
			  },
		    }],
		  ],
          #we need to link to the libeay32.lib
          'libraries': ['-l<(openssl_root)/lib/libeay32.lib' ],
          'include_dirs': ['<(openssl_root)/include'],
        }],
        [ 'OS=="freebsd" or OS=="openbsd" or OS=="mac" or OS=="solaris" or OS=="linux"', {
          'libraries': ['-lssl', '-lcrypto'],
        }],
      ],  
    },
    {
    'target_name': 'webinos_wrt',
    'type': 'none',
    'toolsets': ['host'],
    'copies': [
      {
        'files': [
          '<(PRODUCT_DIR)/certificate_manager.node',
        ],
        'destination': 'node_modules/',
      }],
    }, # end webinos_wrt
  ] # end targets
}

