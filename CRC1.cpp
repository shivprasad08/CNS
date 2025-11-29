//Name: Shivprasad A. Mahind
//PRN: 123B1B266

#include <iostream>
using namespace std;

class CRC {
private:
    int* dataword;
    int* divisor;
    int* codeword;

    int datawordLen;
    int divisorLen;
    int codewordLen;

    void xorDivision(int* temp, int tempLen) {
        for (int i = 0; i <= tempLen - divisorLen; i++) {
            if (temp[i] == 1) {
                for (int j = 0; j < divisorLen; j++) {
                    temp[i + j] ^= divisor[j];
                }
            }
        }
    }

public:
    CRC() {
        dataword = divisor = codeword = nullptr;
        datawordLen = divisorLen = codewordLen = 0;
    }

    ~CRC() {
        delete[] dataword;
        delete[] divisor;
        delete[] codeword;
    }

    void getInput() {
        cout << "Enter the length of dataword (e.g., 8 for ASCII): ";
        cin >> datawordLen;
        dataword = new int[datawordLen];
        cout << "Enter the dataword bits (separated by spaces): ";
        for (int i = 0; i < datawordLen; i++) {
            cin >> dataword[i];
        }

        cout << "Enter the length of divisor: ";
        cin >> divisorLen;
        divisor = new int[divisorLen];
        cout << "Enter the divisor bits (separated by spaces): ";
        for (int i = 0; i < divisorLen; i++) {
            cin >> divisor[i];
        }
    }

    void generateCodeword() {
        codewordLen = datawordLen + divisorLen - 1;

        int* temp = new int[codewordLen];
        for (int i = 0; i < datawordLen; i++) {
            temp[i] = dataword[i];
        }
        for (int i = datawordLen; i < codewordLen; i++) {
            temp[i] = 0;
        }

        xorDivision(temp, codewordLen);
        codeword = new int[codewordLen];

        for (int i = 0; i < datawordLen; i++) {
            codeword[i] = dataword[i];
        }
        for (int i = datawordLen; i < codewordLen; i++) {
            codeword[i] = temp[i];
        }

        cout << "\nRemainder (CRC bits): ";
        for (int i = datawordLen; i < codewordLen; i++) {
            cout << temp[i];
        }

        cout << "\nGenerated Codeword: ";
        for (int i = 0; i < codewordLen; i++) {
            cout << codeword[i];
        }
        cout << endl;
        delete[] temp;
    }

    void checkCodeword() {
        int* received = new int[codewordLen];
        cout << "\nEnter the received codeword bits (" << codewordLen << " bits, separated by spaces): ";
        for (int i = 0; i < codewordLen; i++) {
            cin >> received[i];
        }

        xorDivision(received, codewordLen);

        bool error = false;
        for (int i = datawordLen; i < codewordLen; i++) {
            if (received[i] != 0) {
                error = true;
                break;
            }
        }
        
        if (error) {
            cout << "Error detected in the received codeword.\n";
        } else {
            cout << "No error detected in the received codeword.\n";
        }
        delete[] received;
    }
};

int main() {
    CRC crc_checker;
    crc_checker.getInput();
    crc_checker.generateCodeword();
    crc_checker.checkCodeword();

    return 0;
}