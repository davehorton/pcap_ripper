#include <iostream>

#include "utils.h"

using namespace std ;

/* helper, write a little-endian 32 bit int to memory */
void le32(unsigned char *p, int v)
{
  p[0] = v & 0xff;
  p[1] = (v >> 8) & 0xff;
  p[2] = (v >> 16) & 0xff;
  p[3] = (v >> 24) & 0xff;
}

/* helper, write a little-endian 16 bit int to memory */
void le16(unsigned char *p, int v)
{
  p[0] = v & 0xff;
  p[1] = (v >> 8) & 0xff;
}

/* helper, write a big-endian 32 bit int to memory */
void be32(unsigned char *p, int v)
{
  p[0] = (v >> 24) & 0xff;
  p[1] = (v >> 16) & 0xff;
  p[2] = (v >> 8) & 0xff;
  p[3] = v & 0xff;
}

/* helper, write a big-endian 16 bit int to memory */
void be16(unsigned char *p, int v)
{
  p[0] = (v >> 8) & 0xff;
  p[1] = v & 0xff;
}
