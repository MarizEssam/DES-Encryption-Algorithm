// DES-Encryption-Algorithm.cpp : This file contains the 'main' function. Program execution begins and ends there.

#include <iostream>
#include <fstream>
typedef unsigned long long int ulli;
using namespace std;

//Global Variables
int blocksNumber = 0;
const int maxBlocks = 268435457;
ulli* bitStreams = new ulli[maxBlocks]; //large-sized static array (time consuming)

ulli hexToBin(char ch) {
	ulli bitStream;
	if (ch >= 65) bitStream = (ulli)toupper(ch) - 55;
	else bitStream = (ulli)ch - 48;
	return bitStream;
}

char binToHex(ulli bitStream) {
	return bitStream < 10 ? bitStream + 48 : (bitStream - 10) + 65;
}

ulli* getInputBlocks() {
	//sample_input contains the HEX representation of "It's Hello World"
	//contains: 497427732048656c 6c6f20576f726c64
	ifstream cin("sample_input.txt");

	char ch;
	while (!cin.eof()) {
		ulli bitStream = 0;
		int counter = 0;
		while (counter++ < 16 && cin >> ch) {
			if (ch >= 65) {
				ch = toupper(ch);
				bitStream = bitStream | (((ulli)ch - 55) << (64 - counter * 4));
			}
			else bitStream = bitStream | (((ulli)ch - 48) << (64 - counter * 4));
		}
		if (counter != 1) bitStreams[blocksNumber++] = bitStream;
	}

	return bitStreams;
}

void printBitStream(ulli bitStream) {
	cout << "--Block Started--" << endl;
	int flag = 1;
	int c = 63;
	while (c + 1) {
		cout << ((bitStream >> c) & flag);
		if (c % 4 == 0) cout << endl;
		c--;
	}
	cout << "--Block Ended--" << endl;
}

void printBitStreams(ulli* bitStreams) {
	//logs output to sample_output
#pragma warning(disable : 4996)
	auto F = freopen("sample_output.txt", "w", stdout);

	for (int i = 0; i < blocksNumber; i++) printBitStream(bitStreams[i]);
}

int main() {

	ulli* bitStreams = getInputBlocks();
	printBitStreams(bitStreams);
	//Test conversion subroutines
	//cout << hexToBin('F') << endl;
	//cout << binToHex(6) << endl;

}
