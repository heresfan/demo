#include "algorithm.h"

#include <stdio.h>

int main()
{
    int i;

    int arr[] = {2,1,554,3,22,44,3,1,66,44,3,7,8,9,7,5,54,5,34,5,6};
    /*exchangeSort(arr, sizeof(arr)/sizeof(int));*/
    quickSort(arr, 0, sizeof(arr)/sizeof(int)-1);

    for(i = 0; i < sizeof(arr)/sizeof(int); i ++)
    {
        printf("%d ", arr[i]);
    }
    printf("\n");
}
