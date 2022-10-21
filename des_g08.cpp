// DES-Encryption-Algorithm.cpp : This file contains the 'main' function. Program execution begins and ends there.
#include <iostream>
#include <fstream>
using namespace std;

typedef unsigned long u32;
typedef unsigned long long u64;

#define getBit(index, data)		(data >> index & 1)
#define clearBit(index, data)	(data &= ~(1ULL << index))

//Global Variables
u32 blocksNumber = 0;
const u32 maxBlocks = 268435457;		//max input file size = 2GB ... max number of blocks = 2GB / 8B = 2^31 / 2^3 = 2^28 = 268435456
u64* bitStreams = new u64[maxBlocks];	//large-sized static array (time consuming)
u64 subKeys[16];
u64 bitStream;
string mode;							//Encryption or Decryption mode

//Permutation Tables
const int keyPermutation_1[56] = {
	57, 49, 41, 33, 25, 17,  9,
	 1, 58, 50, 42, 34, 26, 18,
	10,  2, 59, 51, 43, 35, 27,
	19, 11,  3, 60, 52, 44, 36,

	63, 55, 47, 39, 31, 23, 15,
	 7, 62, 54, 46, 38, 30, 22,
	14,  6, 61, 53, 45, 37, 29,
	21, 13,  5, 28, 20, 12,  4
};

const int keyPermutation_2[48] = {
	14, 17, 11, 24,  1,  5,  3, 28, 15,  6, 21, 10,
	23, 19, 12,  4, 26,  8, 16,  7, 27, 20, 13,  2,
	41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
	44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
};

const int left_shifting_iteration[16] = {
	1, 1, 2, 2, 2, 2, 2, 2, 1, 2, 2, 2, 2, 2, 2, 1
};

const int initialPermutation[64] = {
	58, 50, 42, 34, 26, 18, 10,  2,
	60, 52, 44, 36, 28, 20, 12,  4,
	62, 54, 46, 38, 30, 22, 14,  6,
	64, 56, 48, 40, 32, 24, 16,  8,
	57, 49, 41, 33, 25, 17,  9,  1,
	59, 51, 43, 35, 27, 19, 11,  3,
	61, 53, 45, 37, 29, 21, 13,  5,
	63, 55, 47, 39, 31, 23, 15,  7
};

const int ebit_selection_table[48] = {
	32,  1,  2,  3,  4,  5,
	 4,  5,  6,  7,  8,  9,
	 8,  9, 10, 11, 12, 13,
	12, 13, 14, 15, 16, 17,
	16, 17, 18, 19, 20, 21,
	20, 21, 22, 23, 24, 25,
	24, 25, 26, 27, 28, 29,
	28, 29, 30, 31, 32,  1
};

const int s_box[8][4][16] = {
   {
   {14,  4, 13,  1,  2, 15, 11,  8,  3, 10,  6, 12,  5,  9,  0,  7},
   { 0, 15,  7,  4, 14,  2, 13,  1, 10,  6, 12, 11,  9,  5,  3,  8},
   { 4,  1, 14,  8, 13,  6,  2, 11, 15, 12,  9,  7,  3, 10,  5,  0},
   {15, 12,  8,  2,  4,  9,  1,  7,  5, 11,  3, 14, 10,  0,  6, 13},
   },

   {
   {15,  1,  8, 14,  6, 11,  3,  4,  9,  7,  2, 13, 12,  0,  5, 10},
   { 3, 13,  4,  7, 15,  2,  8, 14, 12,  0,  1, 10,  6,  9, 11,  5},
   { 0, 14,  7, 11, 10,  4, 13,  1,  5,  8, 12,  6,  9,  3,  2, 15},
   {13,  8, 10,  1,  3, 15,  4,  2, 11,  6,  7, 12,  0,  5, 14,  9},
   },

   {
   {10,  0,  9, 14,  6,  3, 15,  5,  1, 13, 12,  7, 11,  4,  2,  8},
   {13,  7,  0,  9,  3,  4,  6, 10,  2,  8,  5, 14, 12, 11, 15,  1},
   {13,  6,  4,  9,  8, 15,  3,  0, 11,  1,  2, 12,  5, 10, 14,  7},
   { 1, 10, 13,  0,  6,  9,  8,  7,  4, 15, 14,  3, 11,  5,  2, 12},
   },

   {
   { 7, 13, 14,  3,  0,  6,  9, 10,  1,  2,  8,  5, 11, 12,  4, 15},
   {13,  8, 11,  5,  6, 15,  0,  3,  4,  7,  2, 12,  1, 10, 14,  9},
   {10,  6,  9,  0, 12, 11,  7, 13, 15,  1,  3, 14,  5,  2,  8,  4},
   { 3, 15,  0,  6, 10,  1, 13,  8,  9,  4,  5, 11, 12,  7,  2, 14},
   },

   {
   { 2, 12,  4,  1,  7, 10, 11,  6,  8,  5,  3, 15, 13,  0, 14,  9},
   {14, 11,  2, 12,  4,  7, 13,  1,  5,  0, 15, 10,  3,  9,  8,  6},
   { 4,  2,  1, 11, 10, 13,  7,  8, 15,  9, 12,  5,  6,  3,  0, 14},
   {11,  8, 12,  7,  1, 14,  2, 13,  6, 15,  0,  9, 10,  4,  5,  3},
   },

   {
   {12,  1, 10, 15,  9,  2,  6,  8,  0, 13,  3,  4, 14,  7,  5, 11},
   {10, 15,  4,  2,  7, 12,  9,  5,  6,  1, 13, 14,  0, 11,  3,  8},
   { 9, 14, 15,  5,  2,  8, 12,  3,  7,  0,  4, 10,  1, 13, 11,  6},
   { 4,  3,  2, 12,  9,  5, 15, 10, 11, 14,  1,  7,  6,  0,  8, 13},
   },

   {
   { 4, 11,  2, 14, 15,  0,  8, 13,  3, 12,  9,  7,  5, 10,  6,  1},
   {13,  0, 11,  7,  4,  9,  1, 10, 14,  3,  5, 12,  2, 15,  8,  6},
   { 1,  4, 11, 13, 12,  3,  7, 14, 10, 15,  6,  8,  0,  5,  9,  2},
   { 6, 11, 13,  8,  1,  4, 10,  7,  9,  5,  0, 15, 14,  2,  3, 12},
   },

   {
   {13,  2,  8,  4,  6, 15, 11,  1, 10,  9,  3, 14,  5,  0, 12,  7},
   { 1, 15, 13,  8, 10,  3,  7,  4, 12,  5,  6, 11,  0, 14,  9,  2},
   { 7, 11,  4,  1,  9, 12, 14,  2,  0,  6, 10, 13, 15,  3,  5,  8},
   { 2,  1, 14,  7,  4, 10,  8, 13, 15, 12,  9,  0,  3,  5,  6, 11},
   },
};

const int permutation[32] = {
	16,  7, 20, 21, 29, 12, 28, 17,
	 1, 15, 23, 26,  5, 18, 31, 10,
	 2,  8, 24, 14, 32, 27,  3,  9,
	19, 13, 30,  6, 22, 11,  4, 25
};

const int finalPermutation[64] = {
	40,  8, 48, 16, 56, 24, 64, 32,
	39,  7, 47, 15, 55, 23, 63, 31,
	38,  6, 46, 14, 54, 22, 62, 30,
	37,  5, 45, 13, 53, 21, 61, 29,
	36,  4, 44, 12, 52, 20, 60, 28,
	35,  3, 43, 11, 51, 19, 59, 27,
	34,  2, 42, 10, 50, 18, 58, 26,
	33,  1, 41,  9, 49, 17, 57, 25
};

//Functions
//helper function to specify the logic for reading data from ASCII file
void logicForASCII(char ch, int counter) {
	bitStream = bitStream | ((u64)ch << (64 - counter * 8));
}

//helper function to specify the logic for reading data from HEX file
void logicForHEX(char ch, int counter) {
	if (ch >= 65) {
		ch = toupper(ch);
		bitStream = bitStream | (((u64)ch - 55) << (64 - counter * 4));
	}
	else bitStream = bitStream | (((u64)ch - 48) << (64 - counter * 4));
}

//read HEX data from the specified file
void readData(string fileName, void (*logic)(char, int)) {
	ifstream cin(fileName);

	while (!cin.eof()) {
		char ch;
		bitStream = 0;
		int counter = 0;
		int times = 16;
		if (fileName == "plain.txt") times = 8;
		while (counter++ < times && cin >> noskipws >> ch) {
			logic(ch, counter);
		}
		if (counter != 1 && fileName != "key.txt") bitStreams[blocksNumber++] = bitStream;
	}
}

u32 shift(u32 input, int shiftsNum) {
	u32 result = 0x00;
	for (int i = 0; i < shiftsNum; i++) {
		char bit = getBit(27, input);
		result = input << 1;
		clearBit(28, result);
		result |= (bit & 1);
		input = result;
	}
	return input;
}

u64 permute(u64 plainText, const int* permutationTable, int inputLen, int outputLen) {
	u64 out = 0;
	for (int i = 0; i < outputLen; ++i)
		out |= (plainText >> (inputLen - permutationTable[outputLen - 1 - i]) & 1) << i;
	return out;
}

void keyGenerate(u64 k) {
	u64 effectiveKey = permute(k, keyPermutation_1, 64, 56);  //56 bit output of PC1

	// Dividing 56 bits into two halves 
	u32 D = (effectiveKey & 0x0000000FFFFFFF);	//28 bits
	u32 C = (effectiveKey >> 28);				//28 bits
	u64 CombinedKey = 0;						//C and D combined
	u64 subkey_i = 0;							//48 bit subkey of Round_i

	for (int i = 0; i < 16; i++) {
		// Left Circular Shift
		D = shift(D, left_shifting_iteration[i]);
		C = shift(C, left_shifting_iteration[i]);

		CombinedKey = ((u64)C << 28) | D;
		subkey_i = permute(CombinedKey, keyPermutation_2, 56, 48);   //48 bit output of PC2

		//Pushing subkey into its right place in subkeys array depending on mode
		if (mode == "Encrypt")			subKeys[i] = subkey_i;
		else if (mode == "Decrypt")		subKeys[15 - i] = subkey_i;
	}
}

u32 feistel_function(u32 second_half, u64* subKeys, int round_no) {
	u64 second_half_permuted = permute((u64)second_half, ebit_selection_table, 32, 48);
	u64 xored = second_half_permuted ^ subKeys[round_no];

	u64 mask = 0x0000FC0000000000;
	u32 row, column, sbox_output = 0;
	for (int i = 0; i < 8; i++) {
		char _6bits = 0;
		_6bits = (xored & mask) >> (42 - 6 * i);
		mask = mask >> 6;
		row = ((_6bits & 0b00100000) >> 4) + (_6bits & 1);
		column = (_6bits & 0b00011110) >> 1;
		sbox_output = (sbox_output << 4) | (s_box[i][row][column] & 0b1111);
	}

	return permute((u64)sbox_output, permutation, 32, 32);
}

string binToHEX(u64 bitStream, int length) {
	string str = "";
	for (int i = 0; i < length; i += 4) {
		int shift = length - i - 4;
		u64 temp = bitStream & ((u64)0xF << shift);
		temp = temp >> shift;
		char ch = temp < 10 ? temp + 48 : (temp - 10) + 65;
		str += ch;
	}
	return str;
}

string binToASCII(u64 bitStream, int length) {
	string s = "";
	for (int i = 0; i < 8; i++) {
		int shift = length - 8 * (i + 1);
		s += (bitStream & ((u64)0xFF << shift)) >> shift;
	}
	return s;
}

void clearFiles() {
	remove("debug.txt");
	if (mode == "Encrypt") {
		remove("hex.txt");
		remove("encrypted.txt");
	}
	else if (mode == "Decrypt") remove("decrypt.txt");
}

int main() {
	// mode selection
	cout << "What's your mode? (Encrypt or Decrypt): ";
	cin >> mode;

	//clear output files
	clearFiles();

	//opening output files with appending option enabled
	fstream debug, hex, output_file;
	debug.open("debug.txt", ios::app);
	if (mode == "Encrypt") {
		hex.open("hex.txt", ios::app);
		output_file.open("encrypted.txt", ios::app);
	}
	else if (mode == "Decrypt") output_file.open("decrypt.txt", ios::app);

	//get input data
	if (mode == "Encrypt") readData("plain.txt", logicForASCII);
	else if (mode == "Decrypt") readData("hex.txt", logicForHEX);
	u64* input = bitStreams;

	//get key
	readData("key.txt", logicForHEX);
	u64 key = bitStream;
	keyGenerate(key);

	u64 permuted_input, cipher;
	u32 right_half, left_half, original_right;
	for (u32 i = 0; i < blocksNumber; i++) {
		permuted_input = permute(input[i], initialPermutation, 64, 64);
		right_half = permuted_input & 0x00000000FFFFFFFF;
		left_half = (permuted_input & 0xFFFFFFFF00000000) >> 32;
		debug << "Rounds applied to input block number " << i + 1 << ":\n";

		for (int j = 0; j < 16; j++) {
			original_right = right_half;
			right_half = left_half ^ feistel_function(right_half, subKeys, j);
			left_half = original_right;
			debug << "Round " << j + 1 << " " << binToHEX(left_half, 32) << " " << binToHEX(right_half, 32) << " " << binToHEX(subKeys[j], 48) << endl;
		}

		cipher = permute(((u64)right_half << 32) | left_half, finalPermutation, 64, 64);
		debug << "Cipher text: " << binToHEX(cipher, 64) << "\n\n";
		if (mode == "Encrypt") hex << binToHEX(cipher, 64);
		output_file << binToASCII(cipher, 64);
	}
	debug.close();
	if (mode == "Encrypt") hex.close();
	output_file.close();
	return 0;
}
