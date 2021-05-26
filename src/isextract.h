/* 
 * File:   isextract.h
 * Author: aidan
 *
 * Created on 28 August 2014, 23:29
 */

#ifndef ISEXTRACT_H
#define	ISEXTRACT_H

#ifdef __cplusplus
extern "C" {
#endif

#include "blast.h"
#include <stdbool.h>

typedef struct _ishield3 ishield3;

ishield3 * ishield3_open (const char * filename);
void ishield3_close (ishield3 * is3);
void ishield3_listFiles (ishield3 * is3);
bool ishield3_extractAll (ishield3 * is3, const char * outdir);

#ifdef __cplusplus
}
#endif

#endif	/* ISEXTRACT_H */

