#include "algorithm.h"

int bubbleSort(int *arr, int count)
{
    int temp,
        i,
        j;

    for(i = 0; i < count - 1; i++)
        //count-1 times comparison
    {
        for(j = count - 1; j > i; --j)
            //Everytime we finish a loop, we get a smallest value
        {
            if(arr[j] > arr[j-1])
            {
                temp = arr[j];
                arr[j] = arr[j-1];
                arr[j-1] = temp;
            }
        }
    }

    return 0;
}

int selectSort(int *arr, int count)
{
    int itemp,//store the biggest value
        ipos, //index of the biggest value in the arr
        i,
        j;

    for(i = 0; i < count -1; ++i)
    {
        itemp = arr[i];
        ipos = i;

        for(j = i + 1; j < count; ++j)
        {
            if(itemp < arr[j])
            {
                itemp = arr[j];
                ipos  = j;
            }
        }

        arr[ipos] = arr[i];
        arr[i] = itemp;
    }

    return 0;
}

int insertSort(int *arr, int count)
{
    int itemp,//used to interate the array that not sorted
        ipos, //the position in sorted array
        i;

    for(i = 1; i < count; i++)
    {
        itemp = arr[i];
        ipos = i - 1;

        while(ipos >= 0 && itemp > arr[ipos])
        {
            arr[ipos + 1] = arr[ipos];
            --ipos;
        }

        arr[ipos + 1] = itemp;
    }
}

int exchangeSort(int *arr, int count)
{
    int i,
        j,
        temp;

    for(i = 0; i < count - 1; ++i)
    {
        for(j = i + 1; j < count; ++j)
        {
            if(arr[i] < arr[j])
            {
                temp = arr[i];
                arr[i] = arr[j];
                arr[j] = temp;
            }
        }
    }
}

int quickSort(int *arr, int left, int right)
{
    int middle, //middle value used to switch from left to right
        temp,
        i,
        j;

    i = left, j = right;
    middle = arr[(left + right)/2];

    do
    {
        //get the index value of which is less than the 'middle'
        while(arr[i] > middle && i < right)
            ++i;

        //get the index value of which is lager than the 'middle
        while(arr[j] < middle &&  j > left)
            --j;

        if(i <= j)
        {
            temp = arr[i];
            arr[i] = arr[j];
            arr[j] = temp;

            ++i;
            --j;
        }
    }while(i <= j);

    if(left < j)
        quickSort(arr, left, j);

    if(right > i)
        quickSort(arr, i, right);

}

