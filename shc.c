#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <zlib.h>
#include <openssl/ecdsa.h>
#include <openssl/obj_mac.h>
#include <openssl/sha.h>

#define NUM_OFFSET 48
#define SHC_OFFSET 45

#define BUFFER_SIZE 1024

static const int b64table[256] = {
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
	0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 62, 63, 62, 62, 63,
	52, 53, 54, 55, 56, 57, 58, 59, 60, 61, 0, 0, 0, 0, 0, 0,
	0, 0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14,
	15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 0, 0, 0, 0, 63,
	0, 26, 27, 28, 29, 30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
	41, 42, 43, 44, 45, 46, 47, 48, 49, 50, 51 };

// Assumes to be base64-url encoding with no padding
void unbase64(const char* input, int inLen, unsigned char *output, int *oLen) {
    *oLen = 0;

    for(int i = 0; i < inLen; i += 4) {
	    int n = b64table[input[i]] << 18 | b64table[input[i + 1]] << 12 | b64table[input[i + 2]] << 6 | b64table[input[i + 3]];
	    output[(*oLen)++] = n >> 16;
	    output[(*oLen)++] = n >> 8 & 0xFF;
	    output[(*oLen)++] = n & 0xFF;
    }
}

// Hardcoding data for proof of concept simplicity.  Values are in main below
struct {
	char *kty;
	char *kid;
	char *use;
	char *alg;
	char *crv;
	char *x;
	char *y;
} jwks;


// This would need to be replaced with a valid SHC from a QR code
const char shc[] = "shc:/1234567890";

int main(int argc, char **arv) {
	int idx;
	int outIdx;
	char out[BUFFER_SIZE * 2] = { 0 };

	if(strncmp("shc:/", shc, 5) != 0) {
		printf("payload invalid\n");
		return 1;
	}

	idx = 5;
	for(idx = 5, outIdx = 0; shc[idx] != '\0' && shc[idx+1] != '\0'; idx += 2) {
		out[outIdx++] = ((shc[idx] - NUM_OFFSET) * 10) + (shc[idx+1] - NUM_OFFSET) + SHC_OFFSET;
	}

	if(shc[idx] != '\0') {
		printf("Warning: extraneous byte in payload: %c\n", shc[idx]);
	}

	int encHeaderLen = index(out, '.') - out, decHeaderLen;
	char encHeader[BUFFER_SIZE] = { 0 }, decHeader[BUFFER_SIZE] = { 0 };
	strncpy(encHeader, out, encHeaderLen);
	//printf("encHeader: (%d) %s\n", encHeaderLen, encHeader);

	int encPayloadLen = index(out + encHeaderLen + 1, '.') - out - encHeaderLen - 1, decPayloadLen;
	unsigned char encPayload[BUFFER_SIZE] = { 0 }, decPayload[BUFFER_SIZE] = { 0 };
	strncpy((char*)encPayload, out + encHeaderLen + 1, encPayloadLen);
	//printf("encPayload: (%d) %s\n", encPayloadLen, encPayload);

	int encSigLen = strlen(out) - encHeaderLen - encPayloadLen - 2, decSigLen;
	unsigned char encSig[BUFFER_SIZE] = { 0 }, decSig[BUFFER_SIZE] = { 0 };
	strncpy((char*)encSig, out + encHeaderLen + encPayloadLen + 2, encSigLen);
	//printf("encSig: (%d) %s\n", encSigLen, encSig);


	// This is what the signature is later compared against
	int tokenLen = encHeaderLen + encPayloadLen + 1;
	unsigned char token[BUFFER_SIZE] = { 0 };
	strncpy((char*)token, out, tokenLen);
	//printf("token: %s\n", token);

	// Must be a multiple of 4
	encHeaderLen += encHeaderLen % 4;
	encPayloadLen += encPayloadLen % 4;
	encSigLen += encSigLen % 4;

	unbase64(encHeader, encHeaderLen, (unsigned char*)decHeader, &decHeaderLen);
	unbase64((char*)encPayload, encPayloadLen, decPayload, &decPayloadLen);
	unbase64((char*)encSig, encSigLen, decSig, &decSigLen);

	printf("Header: (%d) %s\n", decHeaderLen, decHeader);
	//printf("decPayload: (%d) [data]\n", decPayloadLen);
	//printf("decSig: (%d) [data]\n", decSigLen);

	// Decompressiong
	unsigned char payload[BUFFER_SIZE * 2] = { 0 };

	z_stream z;
	z.zalloc = Z_NULL;
	z.zfree = Z_NULL;
	z.opaque = Z_NULL;
	z.avail_in = 0;
	z.next_in = Z_NULL;
	if(inflateInit2(&z, -MAX_WBITS) != Z_OK) {
		printf("infalteInit failed\n");
		return 1;
	}

	z.avail_in = decPayloadLen;
	z.next_in = decPayload;
	z.avail_out = sizeof(payload);
	z.next_out = payload;
	int ret = inflate(&z,Z_FINISH);

	printf("Payload: %s\n", payload);

	// Hardcoded values from CA's jwks.json
	// https://myvaccinerecord.cdph.ca.gov/creds/.well-known/jwks.json
	jwks.kty = "EC";
	jwks.kid = "7JvktUpf1_9NPwdM-70FJT3YdyTiSe2IvmVxxgDSRb0";
	jwks.use = "sig";
	jwks.alg = "ES256";
	jwks.crv = "P-256";
	jwks.x = "3dQz5ZlbazChP3U7bdqShfF0fvSXLXD9WMa1kqqH6i4\0\0"; // Buffered to ensure it's a multiple of 4 for unbase64
	jwks.y = "FV4AsWjc7ZmfhSiHsw2gjnDMKNLwNqi2jMLmJpiKWtE\0\0";

	int decXLen, decYLen;
	unsigned char decX[BUFFER_SIZE], decY[BUFFER_SIZE];

	// Hardcoded values, but P-256 will always have 43 byte coords
	// We add one for the unbase64 algorithm
	unbase64(jwks.x, 44, decX, &decXLen);
	unbase64(jwks.y, 44, decY, &decYLen);

	EC_KEY *eckey = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
	if(eckey == NULL) {
		printf("Failed to create new key by name\n");
		return 1;
	}

	BIGNUM *xBN = BN_bin2bn(decX, decXLen - 1, NULL);
	BIGNUM *yBN = BN_bin2bn(decY, decYLen - 1, NULL);

	BIGNUM *rBN = BN_bin2bn(decSig, 32, NULL);
	BIGNUM *sBN = BN_bin2bn(decSig + 32, 32, NULL);

	ECDSA_SIG *sig = ECDSA_SIG_new();
	if(ECDSA_SIG_set0(sig, rBN, sBN) == 0) {
		printf("Error parsing token's signature\n");
		return 1;
	}

	if(EC_KEY_set_public_key_affine_coordinates(eckey, xBN, yBN) == 0) {
		printf("Error with the public key coords.  Cannot validate token\n");
		return 1;
	}

	SHA256_CTX ctx;
	SHA256_Init(&ctx);
	SHA256_Update(&ctx, token, tokenLen);
	unsigned char digest[32] = { 0 };
	SHA256_Final(digest, &ctx);

	int validationResult = ECDSA_do_verify(digest, sizeof(digest), sig, eckey);
	if(validationResult == 1)
		printf("SHC has valid signature\n");
	else if(validationResult == 0)
		printf("SHC failed signature validation\n");
	else
		printf("An error occurred while verifying signature.  Code: %d\n", validationResult);

	BN_free(xBN);
	BN_free(yBN);
	BN_free(rBN);
	BN_free(sBN);
	EC_KEY_free(eckey);

	return 0;
}
