/*
 * @Author: Samrito
 * @Date: 2022-03-01 22:03:56
 * @LastEditors: Samrito
 * @LastEditTime: 2022-03-01 22:05:02
 */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
int main() {
  time_t seed = time(NULL);
  srand(seed);
  for (int i = 0; i <= 49; ++i) {
    int num = rand() % 100;
    printf("%d\n", num);
  }
  return 0;
}