//Applied Cryptography - Patorn, Khoa, Deepthi
//ElGamal encryption and decryption implementation
#include <iostream>
#include <string>
#include <sstream>
#include <cmath>
using namespace std;



int main()
{
	int pr;
	bool Found = false;
	do {
		cout << "Enter a prime number:";
		cin >> pr;
		int count = 0; //reset counter
		for (int ii = 1; ii < pr; ii++) {
			if (pr%ii == 0)
				count += 1;

			if (count == 2) {
				cout << "pr " << pr << " is NOT prime" << endl;
				Found = false;
				break;

			}
		}
		if (count == 1)

		{
			cout << "pr " << pr << " is prime" << endl;
			Found = true;
		}

	} while (Found == false);

	cout << "Congratulation! You have found a prime pr: " << pr << endl;
	//Now enter g number
	int gg;

	do {
		cout << "Enter a G number; G should be in range (1, " << pr - 1 << ")" << endl;
		cin >> gg;

	} while (gg >= pr || gg <= 1);


	//Enter secret key
	int xx;
	do {
		cout << "Select a random number for your secret key; x in range (1, " << pr - 1 << ")" << endl;
		cin >> xx;

	} while (xx >= pr || xx <= 1);
	cout << "Your SECRET KEY is: " << xx << endl;


	unsigned long long yy = pow(gg, xx);
	// Calculate Y = (G to the power of xx) mod P
	yy = yy%pr;

	cout << "The PUBLIC KEYs are (use these parameters to do the encryption): ";
	cout << "p= " << pr << " and G = " << gg << " and Y= " << yy << endl;

	//Encryption
	//5 represents any letter we want
	int message = 5;
	int k = 0;
	do {
		cout << "Select a random number for your k; k in range (1, " << pr - 1 << ")" << endl;
		cin >> k;

	} while (k >= pr || k <= 1);
	cout << "Your k is: " << k << endl;

	unsigned long long gamma = 0;
	gamma = pow(gg, k);
	gamma = gamma%pr;
	cout << "gamma is " << gamma << endl;

	unsigned long long delta = 0;
	delta = message * pow(yy,k);
	delta = delta%pr;
	cout << "delta is " << delta;
	cout << "Ciphertext is (" << gamma << "," << delta << ")" << endl;

	//Decryption
	int decrypted_message = 0;
	int power = 0;
	power = pr - 1 - xx;
	cout << "power is " << power << endl;
	unsigned long long decrypt = 0;
	decrypt = pow(gamma, power);
	decrypt = decrypt%pr;
	decrypted_message = (decrypt * delta) % pr;
	cout << "decrypted_message is " << decrypted_message << endl;



	//system("PAUSE");
    return (0);
}

