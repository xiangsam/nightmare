/*
 * @Author: Samrito
 * @Date: 2022-03-01 21:43:48
 * @LastEditors: Samrito
 * @LastEditTime: 2022-03-01 21:57:18
 */
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
int main() {
  long long nums[] = {121, 1231231, 20312312, 122342342, 90988878, -30};
  time_t v3 = time(NULL);
  srand(v3);
  for (int i = 0; i <= 5; ++i) {
    nums[i] -= rand() % 10 - 1;
  }
  long long v9 = 0;
  for (int i = 0; i <= 5; ++i) {

    v9 += nums[i];
  }
  printf("%lld", v9);
  return 0;
}