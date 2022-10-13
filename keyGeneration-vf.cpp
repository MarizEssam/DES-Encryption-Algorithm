#include <iostream>
#define clearBit(index, data) (data &= ~(1ULL << index))
#define setBit(index, data) (data |= u64(1ULL << index))
#define getBit(index, data) (data >> index & 1)
using namespace std;

typedef unsigned long long u64;

int keypermutation_1[56] = { 57, 49, 41, 33, 25, 17, 9,
                 1, 58, 50, 42, 34, 26, 18,
                 10, 2, 59, 51, 43, 35, 27,
                 19, 11, 3, 60, 52, 44, 36,

                 63, 55, 47, 39, 31, 23, 15,
                 7, 62, 54, 46, 38, 30, 22,
                 14, 6, 61, 53, 45, 37, 29,
                 21, 13, 5, 28, 20, 12, 4
               };

int keypermutation_2[48] = { 14, 17, 11, 24, 1, 5, 3, 28, 15, 6, 21, 10,
                                23, 19, 12, 4, 26, 8, 16, 7, 27, 20, 13, 2,
                                41, 52, 31, 37, 47, 55, 30, 40, 51, 45, 33, 48,
                                44, 49, 39, 56, 34, 53, 46, 42, 50, 36, 29, 32
                              };

int LeftShiftingIteration[16] = { 1, 1, 2, 2,
                       2, 2, 2, 2,
                       1, 2, 2, 2,
                       2, 2, 2, 1
                     };

int ebit_selection_table[48] = {32, 1, 2, 3, 4, 5,
                                4, 5, 6, 7, 8, 9,
                                8, 9, 10, 11, 12, 13,
                                12, 13, 14, 15, 16, 17,
                                16, 17, 18, 19, 20, 21,
                                20, 21, 22, 23, 24, 25,
                                24, 25, 26, 27, 28, 29,
                                28, 29, 30, 31, 32, 1
                               };

u64 shift(u64 input, int shiftsNum){
  u64 result = 0x00;
  for (int i = 0; i < shiftsNum; i++) {
    u64 bit = u64(getBit(27, input));
    result = input << 1;
    clearBit(28, result);
    result |= bit;
    input = result;
  }
  return input;
}

u64 permute(u64 plainText, int * permutationTable, int inputLen, int outputLen){
  u64 out=0;
  for(int i=0;i<outputLen;++i)
  out|=(plainText>>(inputLen-permutationTable[outputLen-1-i])&1)<<i;
  return out;
}

u64 subKeys[16];
u64 * keyGenerate(u64 key)
{
  key = permute(key, keypermutation_1, 64, 56);
  u64 rightSubkey = key & 0xFFFFFFF;
  u64 leftSubkey = (key & 0x00FFFFFFF0000000) >> 28;
  for (int i = 0; i < 16; i++) {
    leftSubkey = shift(leftSubkey, LeftShiftingIteration[i]);
    rightSubkey = shift(rightSubkey, LeftShiftingIteration[i]);
    u64 combinedKey = (leftSubkey<<28) | rightSubkey;
    u64 subKey = permute(combinedKey, keypermutation_2, 56, 48);
    cout<<subKey<<endl;
    subKeys[i] = subKey;
  }
  return subKeys;
}

u64 input = 0x497427732048656c;

u64 permute_xor(u64 input, u64 *subKeys, int round_no)
{
  u64 second_half = input & 0xFFFFFFFF;
  u64 second_half_permuted = permute(second_half, ebit_selection_table, 32, 48);
  u64 xored = second_half_permuted ^ subKeys[round_no];
  printf("xored: %016llX\n", xored);
  return xored;
}

    int main()
    {
        
             //uint64_t key2 =  0x0123456789ABCDEF;
             uint64_t key = 0x133457799BBCDFF1;
             keyGenerate(key);
             int round_no = 1;
             permute_xor(input, subKeys, round_no);
             return 0;

    }
