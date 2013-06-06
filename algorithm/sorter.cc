#include "sorter.h"

extern "C"
{
#include "algorithm.h"
}

int sorter::selectSort(int *arr, int count)
{
    return ::selectSort(arr, count);
}

int sorter::exchangeSort(int *arr, int count)
{
    return ::exchangeSort(arr, count);
}

int sorter::insertSort(int *arr, int count)
{
    return ::insertSort(arr, count);
}

int sorter::bubbleSort(int *arr, int count)
{
    return ::bubbleSort(arr, count);
}

int sorter::quickSort(int *arr, int count)
{
    return ::quickSort(arr, 0, count-1);
}

