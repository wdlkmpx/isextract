/* 
 * File:   isextract.h
 * Author: aidan
 *
 * Created on 28 August 2014, 23:29
 */

#ifndef ISEXTRACT_H
#define	ISEXTRACT_H

#include "blast.h"

#ifdef _WIN32
#define DIR_SEPARATOR '\\'
#include "win32/stdint.h"
#else
#define DIR_SEPARATOR '/'
#include <stdint.h>
#endif

typedef struct _is3_file is3_file;
struct _is3_file {
    char * name;
    uint32_t compressed_size;
    uint32_t uncompressed_size;
    uint32_t offset;
    uint32_t datetime;
    is3_file * next;
};


class InstallShield
{
public:
    InstallShield();
    ~InstallShield();
    void open (const char * filename);
    void close();
    void listFiles();
    bool extractFile (const char *find_filestr, is3_file * selected_file, const char *outdir);
    bool extractAll (const char *outdir);
private:

    uint32_t parseDirs();
    void parseFiles();
    is3_file * m_files;
    char * m_filename;
    FILE * file_handle;
    uint32_t m_dataoffset;
    uint32_t m_datasize;
    is3_file * m_current_file;
    int32_t m_file_remaining;
};

#endif	/* ISEXTRACT_H */

