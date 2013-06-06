#include "sorter.h"

#include <stdio.h>

int main()
{
    int arr[] = {3,11,2,564,34,4,5,3,4,5,4,34,534,6,7,6,64,34,5,56,45,7};
    int size = sizeof(arr) / sizeof(int);

    sorter::quickSort(arr, size);

    for(int i = 0; i < size; ++i)
    {
        printf("%d ", arr[i]);
    }
    printf("\n");
}
