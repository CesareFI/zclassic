/* Copyright 2026 Rhett Creighton; SPDX-License-Identifier: Apache-2.0
 * purpose: Admit and open bounded Apple Silicon HUD parts with explicit host ownership. */
#include "part_open.h"
#include "zsha256/zsha256.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
static struct sky_open_result refusal(enum sky_open_verdict verdict,
 enum sky_macho_verdict admission,enum sky_load_verdict loader)
{
 fprintf(stderr,"sky_part_open refusal=%d admission=%d loader=%d\n",
  (int)verdict,(int)admission,(int)loader);
 return (struct sky_open_result){verdict,admission,loader};
}
struct sky_open_result sky_part_open(struct sky_part_host *host,const void *bytes,
 size_t n,const uint8_t expected[32])
{
 if(!host || !bytes || !expected || !n || n>16u*1024u*1024u)
  return refusal(SKY_OPEN_ARGUMENT,SKY_MACHO_ARGUMENT,SKY_LOAD_ARGUMENT);
 uint8_t digest[32],wanted[32];memcpy(wanted,expected,sizeof(wanted));
 uint8_t *snapshot=malloc(n);
 if(!snapshot)return refusal(SKY_OPEN_MEMORY,SKY_MACHO_ARGUMENT,SKY_LOAD_MEMORY);
 memcpy(snapshot,bytes,n);zsha256(snapshot,n,digest);
 if(zsha256_compare(digest,wanted)){
  free(snapshot);return refusal(SKY_OPEN_DIGEST,SKY_MACHO_DIGEST,SKY_LOAD_ADMISSION);
 }
 enum sky_macho_verdict admission=sky_part_admit_macho(snapshot,n,wanted);
 if(admission!=SKY_MACHO_ADMIT){
  free(snapshot);return refusal(SKY_OPEN_ADMISSION,admission,SKY_LOAD_ADMISSION);
 }
 enum sky_load_verdict loaded=sky_part_load(host,snapshot,n,wanted);
 free(snapshot);
 if(loaded!=SKY_LOAD_OK)return refusal(SKY_OPEN_LOADER,SKY_MACHO_ADMIT,loaded);
 return (struct sky_open_result){SKY_OPEN_OK,SKY_MACHO_ADMIT,SKY_LOAD_OK};
}
