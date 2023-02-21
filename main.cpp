#include <iostream>
#include <fstream>
#include <string>
#include <stdio.h>
#include <vector>
#include <tuple>
#include <map>
#include "NTL/ZZ.h"


#include "hash.h"

using namespace std;
using namespace NTL;

std::map<char, uint> hexNumber;
NTL::ZZ C3;


typedef std::pair<NTL::ZZ, NTL::ZZ> KEY_PAIR;

NTL::ZZ readHexNumber(fstream & inputFile) {
	NTL::ZZ p = conv<ZZ>(0);
	std::string fileLine;
	std::getline(inputFile, fileLine);
	for (size_t i = 0; i < fileLine.size(); i++) {
		char c = fileLine[i];
		if (isdigit(c))
			p = 16*p + (c - '0');
		else
			p = 16*p + hexNumber[c];
	}
	return p;
}

bool checkParameters(const NTL::ZZ & p, const NTL::ZZ & q, const NTL::ZZ & a) {

	if ( (p - 1) % q != 0) {
		std::cout << "(p - 1)(mod q) != 0" << std::endl;
		return false;
	}

	if (NTL::PowerMod(a, q, p) != 1) {
		std::cout << "a^q(mod p) != 1" << std::endl;
		return false;
	}
	return true;
}

KEY_PAIR generateKeyPair(const NTL::ZZ & privateKey, const NTL::ZZ & a, const NTL::ZZ & p) {
	KEY_PAIR result;
	NTL::ZZ publicKey = NTL::PowerMod(a, privateKey, p);
	return std::make_pair(privateKey, publicKey);
}





NTL::ZZ P(const NTL::ZZ & n) {
	NTL::ZZ result;
	return result;
}

NTL::ZZ A(const NTL::ZZ & n) {
	NTL::ZZ result;
	return result;	
}

std::vector<NTL::ZZ> generateKeys(const NTL::ZZ & H,  const NTL::ZZ & M) {

	std::vector<NTL::ZZ> keys;
	NTL::ZZ U = H;
	NTL::ZZ V = M;
	NTL::ZZ W;
	
	NTL::bit_xor(W, U, V);
	keys.push_back(P(W));
	
	U = A(U);
	V = A(A(V));
	NTL::bit_xor(W, U, V);
	keys.push_back(P(W));

	NTL::bit_xor(U, A(U), C3);
	V = A(A(V));
	NTL::bit_xor(W, U, V);
	keys.push_back(P(W));
	U = A(U);
	V = A(A(V));
	NTL::bit_xor(W, U, V);
	keys.push_back(P(W));	

	return keys;
}



NTL::ZZ encryptionTransform(const NTL::ZZ & H, const std::vector<NTL::ZZ> & keys) {
	NTL::ZZ result;
	return result;
}


NTL::ZZ gostR3411(const NTL::ZZ & input) {
	NTL::ZZ result;
	return result;
}


NTL::ZZ generateKEK(const NTL::ZZ & privateKey, const NTL::ZZ & publicKey, const NTL::ZZ & p) {
	NTL::ZZ k = PowerMod(publicKey, privateKey, p);
	NTL::ZZ kek = gostR3411(k);
	return kek;
}

bool checkKeyPair(KEY_PAIR pair, const NTL::ZZ & a, const NTL::ZZ & p) {
	if (pair.second % p == a % p)
		return false;

	return true;
}


int main(int argc, char * argv[] ) {
	NTL::ZZ p, q, a, x, y;
	p = q = a = x = y = C3 = 0;
	hexNumber['A'] = 10;
	hexNumber['B'] = 11;
	hexNumber['C'] = 12;
	hexNumber['D'] = 13;
	hexNumber['E'] = 14;
	hexNumber['F'] = 15;
	
	if (argc != 2) {
		std::cout << "Try " << argv[0] << " <parameters_file>"  << std::endl;
		return 1;
	}

	std::fstream inputFile;
	inputFile.open(argv[1]);

	p = readHexNumber(inputFile);
	q = readHexNumber(inputFile);
	a = readHexNumber(inputFile);
	x = readHexNumber(inputFile);
	y = readHexNumber(inputFile);
	C3 = readHexNumber(inputFile);
	if (!checkParameters(p, q, a)) {
		std::cout << "PARAMETERS ARE INCORRECT" << std::endl;
		return 1;
	}

	std::cout << "PARAMETERS ARE CORRECT" << std::endl;
	
	KEY_PAIR sender = generateKeyPair(x, a, p);
	KEY_PAIR recipient = generateKeyPair(y, a, p);

	if (!checkKeyPair(sender, a, p) || 
		!checkKeyPair(recipient, a, p) ||
		NTL::PowerMod(sender.second, recipient.first, p) !=  
		NTL::PowerMod(recipient.second, sender.first, p) ) {
		std::cout << "KEYS ARE INCORRECT" << std::endl;
		return 1;
	}

	std::cout << "KEYS ARE CORRECT" << std::endl;
	std::cout << "HASH FUNCTION\n" << std::endl;
	HASH hash;

	
	unsigned char test_text3[10] =
	{
		0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61, 0x61,
		0x61, 0x61
	};

	unsigned char test_text2[50] = 
	{
		0x53, 0x75, 0x70, 0x70, 0x6f, 0x73, 0x65, 0x20, 
		0x74, 0x68, 0x65, 0x20, 0x6f, 0x72, 0x69, 0x67,
		0x69, 0x6e, 0x61, 0x6c, 0x20, 0x6d, 0x65, 0x73,
		0x73, 0x61, 0x67, 0x65, 0x20, 0x68, 0x61, 0x73,	
		0x20, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x20,
		0x3d, 0x20, 0x35, 0x30, 0x20, 0x62, 0x79, 0x74,
		0x65, 0x73      
	};


	unsigned char test_text1[32] = {  	
		0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 
		0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x2c, 
		0x20, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x3d, 	
		0x33, 0x32, 0x20, 0x62, 0x79, 0x74, 0x65, 0x73, 
	};

	unsigned char test_text4[178] = {  	
		0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 
		0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x2c, 
		0x20, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x3d, 
		0x33, 0x32, 0x20, 0x62, 0x79, 0x74, 0x65, 0x73, 
		0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 
		0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x2c, 
		0x20, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x3d, 
		0x33, 0x32, 0x20, 0x62, 0x79, 0x74, 0x65, 0x73, 
		0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 
		0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x2c, 
		0x20, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x3d, 
		0x33, 0x32, 0x20, 0x62, 0x79, 0x74, 0x65, 0x73, 
		0x54, 0x68, 0x69, 0x73, 0x20, 0x69, 0x73, 0x20, 
		0x6d, 0x65, 0x73, 0x73, 0x61, 0x67, 0x65, 0x2c, 
		0x20, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x3d, 
		0x33, 0x32, 0x20, 0x62, 0x79, 0x74, 0x65, 0x73, 
		0x53, 0x75, 0x70, 0x70, 0x6f, 0x73, 0x65, 0x20, 
		0x74, 0x68, 0x65, 0x20, 0x6f, 0x72, 0x69, 0x67,
		0x69, 0x6e, 0x61, 0x6c, 0x20, 0x6d, 0x65, 0x73,
		0x73, 0x61, 0x67, 0x65, 0x20, 0x68, 0x61, 0x73,	
		0x20, 0x6c, 0x65, 0x6e, 0x67, 0x74, 0x68, 0x20,
		0x3d, 0x20, 0x35, 0x30, 0x20, 0x62, 0x79, 0x74,
		0x65, 0x73
	};


	gostHash(&hash, test_text4, 178);

	printf("\n\nRESULTHASH:\n");
	for (size_t i = 0; i < 32; i++) {
		char l = (hash.result[i] & 0xf0) >> 4;
		char r = hash.result[i] & 0x0f;
			printf("%x%x",l,r);
	}
	printf("\n");
	return 0;
}
