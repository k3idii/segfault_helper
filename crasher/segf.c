#include <stdlib.h>
int main(int argc, char* argv[]){
  return argc<=1?0:1==((unsigned char*)0)[strtol(argv[1],0,16)];
}
