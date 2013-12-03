#include "ace/OS.h"

#include <iostream>

int main()
{
    ACE_Time_Value tv;
    tv = ACE_OS::gettimeofday();

    std::cout << "Hello World!! " << tv.sec() << " second has elapsed since EPOCH 1970 01 01 00:00:00" << std::endl;

    while(1)
    {
        if((ACE_OS::gettimeofday() - tv).sec() == 5)
        {
            printf("5 seconds has been past\n");
            exit(0);
        }
    }
}
