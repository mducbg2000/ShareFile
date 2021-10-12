#include <iostream>
#include "FileHandle.h"
#include "Crypt.h"
int main(int argc, char* args[])
{
	switch (args[1][0])
	{
		// generate key pair
		case 'g': 
			std::cout << "Generate key pair";
			// generate key pair for your self
			if (strlen(args[2]) <= 0) 
				genKeyPair(args[2]);
			else 
				goto failed_args;
			break;

		case 'e':
			std::cout << "Encrypt File";
			encryptFile(args[2], args[3], args + 4);
			break;
		
		case 'd':
			std::cout << "Decrypt File";
			decryptFile(args[2], args[3], args[4], args[5]);
			break;

		default:
			failed_args:
			std::cout << "Failed arguments!";
			return 1;
	}

	return 0;
}

