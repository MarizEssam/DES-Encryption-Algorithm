// DES-Encryption-Algorithm.cpp : This file contains the 'main' function. Program execution begins and ends there.

#include <iostream>
#include <fstream>
#include <vector>
typedef unsigned long long int ulli;
using namespace std;

vector<ulli>* getInputBlocks() {
	//sample_input contains the HEX representation of "It's Hello World"
	//contains: 497427732048656c 6c6f20576f726c64
	ifstream cin("sample_input.txt");

	vector<ulli>* bitStreams = new vector<ulli>;
	char ch;
	while (!cin.eof()) {
		ulli bitStream = 0;
		int counter = 0;
		while (counter++ < 16 && cin >> ch) {
			if (ch >= 65) {
				ch = toupper(ch);
				bitStream = bitStream | ((ulli)(ch - 55) << (64 - counter * 4));
			}
			else bitStream = bitStream | ((ulli)(ch - 48) << (64 - counter * 4));
		}
		if (counter != 1) (*bitStreams).push_back(bitStream);
	}

	return bitStreams;
}

void printBitStreams(vector<ulli>* bitStreams) {
	//logs output to sample_output
#pragma warning(disable : 4996)
	auto F = freopen("sample_output.txt", "w", stdout);

	for (auto bitStream : *bitStreams) {
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
}

int main() {

	vector<ulli>* bitStreams = getInputBlocks();
	printBitStreams(bitStreams);

}
