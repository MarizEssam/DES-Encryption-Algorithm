
#include <iostream>
typedef unsigned long long u64;
using namespace std;

    u64 PC1[56] = { 57,49,41,33,25,17,9,
                    1,58,50,42,34,26,18,
                    10,2,59,51,43,35,27,
                    19,11,3,60,52,44,36,
                    63,55,47,39,31,23,15,
                    7,62,54,46,38,30,22,
                    14,6,61,53,45,37,29,
                    21,13,5,28,20,12,4 };                                

    u64 PC2[48] = { 14,17,11,24,1,5,
                    3,28,15,6,21,10,
                    23,19,12,4,26,8,
                    16,7,27,20,13,2,
                    41,52,31,37,47,55,
                    30,40,51,45,33,48,
                    44,49,39,56,34,53,
                    46,42,50,36,29,32 };

    int LeftShiftIterations[16] = { 1,1,2,2,2,2,2,2,1,2,2,2,2,2,2,1 };

    string Mode;  // Encryption or Decryption mode
    u64 Subkeys[16] = { 0 };

// Function to take key as string from user and convert it to u64
u64 read_DES_key(string Data)
{

    u64 value = 0;
    for (int i = 0; i < Data.length(); ++i)
    {
        char c = Data[i];
        if (c >= '0' && c <= '9')
        {
            value |= (u64)(c - '0') << ((15 - i) << 2);
        }
        else if (c >= 'A' && c <= 'F')
        {
            value |= (u64)(c - 'A' + 10) << ((15 - i) << 2);
        }
        else if (c >= 'a' && c <= 'f')
        {
            value |= (u64)(c - 'a' + 10) << ((15 - i) << 2);
        }
    }
    return value;
}

// Shifting Function 
u64 LeftShift(u64 left_key, int round)
{
    u64 temp = 0;
    
        if (round == 1)
        {
            temp = left_key & (0x7FFFFFF);
          
            left_key = (temp << 1) | left_key>>27;
          
        }

        else if (round == 2)
        {
            temp = left_key& (0x3FFFFFF);
     
            left_key = (temp << 2) | left_key>>26;
           
        }
   
    return left_key;
};

u64 permute(u64 input, u64 permTable[], int inputsize, int outputsize )
{
    u64 output = 0;
    for (int i = 0; i < outputsize; ++i)

    {
        output |= (input >> (inputsize - permTable[i]) & 1) << outputsize - (i + 1);
    }
    return output;
}


void keygen(string k){
    u64  Key_read = read_DES_key(k);
    u64 PC1_output = permute(Key_read, PC1, 64, 56);  //56 bit output
    // Dividing 56 bits into two halves 
    u64 C = PC1_output;
    u64 D = PC1_output;
    D = (D & 0x0000000FFFFFFF);   //28 bits
    C = (C >> 28);               //28 bits
    u64 CombinedKey = 0;   // C and D combined
    u64 subkey_i = 0;  //48 bit subkey of Round_i

// Left Circular Shift
    for (int i = 0; i < 16; i++)
    {

        D = LeftShift(D, LeftShiftIterations[i]);
        C = LeftShift(C, LeftShiftIterations[i]);
        CombinedKey = (C << 28);
        CombinedKey = (CombinedKey | D);
        subkey_i = permute(CombinedKey, PC2, 56, 48);   // 48 bit output of PC2
        //cout<<subkey_i<<endl;
        //Pushing subkey into its right place in subkeys array depending on mode
        if (Mode == "Encrypt")
        {
            Subkeys[i] = subkey_i;

        }
        else  if (Mode == "Decrypt")
        {
            Subkeys[15 - i] = subkey_i;
        }
}
}

//for testing
void printsubkey(string key){
    keygen(key);
    for(int i = 0 ; i<16 ; i++){
        cout<<std::hex<<Subkeys[i]<<endl;
    }

}


//test
int main(){
    string Key;
    cout<< "Enter The Key: "<< endl;
    cin >> Key;
    
    cout<<"What's your Mode Encrypt or Decrypt: "<< endl;
    cin >> Mode;
    printsubkey(Key);

}