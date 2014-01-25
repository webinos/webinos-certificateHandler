// Code copied from node.js as this is not an external function any more.
// https://github.com/joyent/node
#include "nodeHiddenExports.h"

enum encoding nodeHiddenExports::ParseEncoding(Handle<Value> encoding_v) {
	HandleScope scope;

	if (!encoding_v->IsString()) return UTF8;

	String::Utf8Value encoding(encoding_v);

	if (strcasecmp(*encoding, "utf8") == 0) {
		return UTF8;
	}
	else if (strcasecmp(*encoding, "utf-8") == 0) {
		return UTF8;
	}
	else if (strcasecmp(*encoding, "ascii") == 0) {
		return ASCII;
	}
	else if (strcasecmp(*encoding, "base64") == 0) {
		return BASE64;
	}
	else if (strcasecmp(*encoding, "ucs2") == 0) {
		return UCS2;
	}
	else if (strcasecmp(*encoding, "ucs-2") == 0) {
		return UCS2;
	}
	else if (strcasecmp(*encoding, "utf16le") == 0) {
		return UCS2;
	}
	else if (strcasecmp(*encoding, "utf-16le") == 0) {
		return UCS2;
	}
	else if (strcasecmp(*encoding, "binary") == 0) {
		return BINARY;
	}
#if !defined(ANDROID)
    // Anode doesn't have this value
	else if (strcasecmp(*encoding, "buffer") == 0) {
		return BUFFER;
	}
#endif
	else if (strcasecmp(*encoding, "hex") == 0) {
		return HEX;
	}
	else if (strcasecmp(*encoding, "raw") == 0) {
#if !defined(ANDROID)
		// Anode doesn't have this value
		if (!no_deprecation) {
			fprintf(stderr, "'raw' (array of integers) has been removed. "
				"Use 'binary'.\n");
		}
#endif
		return BINARY;
	}
	else if (strcasecmp(*encoding, "raws") == 0) {
#if !defined(ANDROID)
		// Anode doesn't have this value
		if (!no_deprecation) {
			fprintf(stderr, "'raws' encoding has been renamed to 'binary'. "
				"Please update your code.\n");
		}
#endif
		return BINARY;
	}
	else {
		return UTF8;
	}
}
