#include <iostream>
#include <random>
#include "SessionIO.hpp"

int main(int argc, char* argv[])
{
	try
	{
		srand(unsigned(time(NULL)));
		SessionIO obj;
		obj.Run();
	}
	catch (...)
	{

	}

	return 0;
}