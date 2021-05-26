#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <utime.h>
#include <string.h>
#include <stdint.h>

#include "isextract.h"
#include "dostime.h"


#ifdef _WIN32
#define DIR_SEPARATOR '\\'
#include "win32/stdint.h"
#else
#define DIR_SEPARATOR '/'
#include <stdint.h>
#endif

// =================================================================

typedef struct _is3_dir is3_dir;
struct _is3_dir {
    uint32_t count;
    is3_dir * next;
};

typedef struct _is3_file is3_file;
struct _is3_file
{
    char * name;
    uint32_t compressed_size;
    uint32_t uncompressed_size;
    uint32_t offset;
    uint32_t datetime;
    is3_file * next;
};

struct _ishield3
{
    is3_file * files;
    char * archive_fname;
    FILE * archive_fd;
    uint32_t dataoffset;
    uint32_t datasize;
};

// =================================================================

const uint32_t signature = 0x8C655D13;
const int32_t data_start = 255;
#define CHUNK 16384
/*const uint32_t YR_MASK  = 0xFE000000;
const uint32_t MON_MASK = 0x01E00000;
const uint32_t DAY_MASK = 0x001F0000;
const uint32_t HR_MASK  = 0x0000F800;
const uint32_t MIN_MASK = 0x000007E0;
const uint32_t SEC_MASK = 0x0000001F;*/

// =================================================================

static uint32_t parseDirs  (ishield3 * is3);
static void     parseFiles (ishield3 * is3);
static bool extractFile (ishield3 * is3, const char *find_filestr, is3_file * selected_file, const char *outdir);

// blast.c callbacks
static unsigned inf(void *how, unsigned char **buf)
{
    static unsigned char hold[CHUNK];

    *buf = hold;
    return fread(hold, 1, CHUNK, (FILE *)how);
}

static int outf(void *how, unsigned char *buf, unsigned len)
{
    return fwrite(buf, 1, len, (FILE *)how) != len;
}

// =================================================================


ishield3 * ishield3_open (const char * filename)
{
    uint32_t sig;
    int32_t toc_address;
    uint16_t dir_count;
    FILE * fd;

    fd = fopen (filename, "rb");
    if (!fd) {
        return NULL;
    }

    // init
    ishield3 * is3 = (ishield3*) calloc (1, sizeof(ishield3));
    is3->archive_fd  = fd;
    is3->archive_fname   = strdup (filename);
    is3->dataoffset = data_start;
    is3->datasize   = 0;
    is3->files      = NULL;

    // read signature
    fread (&sig, sizeof(uint32_t), 1, is3->archive_fd);
    
    //test if we have what we think we have
    if (sig != signature) {
        fprintf (stderr, "Not a valid InstallShield 3 archive\n");
        return NULL;
    }
    
    //get some basic info on where stuff is in file
    fseek (is3->archive_fd, 37, SEEK_CUR);
    fread ((void*) &toc_address, sizeof(int32_t), 1, is3->archive_fd);
    
    fseek (is3->archive_fd, 4, SEEK_CUR);
    fread ((void*) &dir_count, sizeof(uint16_t), 1, is3->archive_fd);

    //find the toc and work out how many files we have in the archive
    fseek (is3->archive_fd, toc_address, SEEK_SET);

    is3_dir * dirfiles = NULL;
    is3_dir * currentdir = NULL, * dirtemp = NULL;

    for(uint32_t i = 0; i < dir_count; i++)
    {
        dirtemp = (is3_dir*) calloc (1, sizeof(is3_dir));
        dirtemp->count = parseDirs(is3);
        if (!dirfiles) {
           dirfiles = dirtemp;
        } else if (currentdir) {
           currentdir->next = dirtemp;
        }
        currentdir = dirtemp;
    }

    //parse the file entries in the toc to get filenames, size and location
    currentdir = dirfiles;
    while (currentdir)
    {
        for(uint32_t j = 0; j < currentdir->count; j++) {
            parseFiles (is3);
        }
        dirtemp = currentdir->next;
        free (currentdir);
        currentdir = dirtemp;
    }

    fclose (is3->archive_fd);
    return is3;
}


void ishield3_close (ishield3 * is3)
{
    // free data
    if (is3->archive_fname) {
        free (is3->archive_fname);
        is3->archive_fname = NULL;
    }
    if (is3->files) {
       is3_file * it = is3->files, * nextfile;
       while (it)
       {
           nextfile = it->next;
           if (it->name) free (it->name);
           free (it);
           it = nextfile;
       }
    }
    if (is3) {
       free (is3);
    }
}


static uint32_t parseDirs (ishield3 * is3)
{
    uint16_t fcount;
    uint16_t chksize;
    uint16_t nlen;
    
    fread ((void*) &fcount,  sizeof(uint16_t), 1, is3->archive_fd);
    fread ((void*) &chksize, sizeof(uint16_t), 1, is3->archive_fd);
    fread ((void*) &nlen,    sizeof(uint16_t), 1, is3->archive_fd);

    printf ("We have %u files\n", fcount);
    
    //skip the name of the dir, we just want the files
    fseek (is3->archive_fd, nlen, SEEK_CUR);
    
    //skip to end of chunk
    fseek (is3->archive_fd, chksize - nlen - 6, SEEK_CUR);

    return fcount;
}


static void parseFiles (ishield3 * is3)
{
    is3_file * file = (is3_file*) calloc (1, sizeof(is3_file));
    is3_file * it;
    uint16_t chksize;
    uint8_t namelen;

    fseek (is3->archive_fd, 3, SEEK_CUR);
    fread ((void*) &(file->uncompressed_size), sizeof(uint32_t), 1, is3->archive_fd);
    fread ((void*) &(file->compressed_size),   sizeof(uint32_t), 1, is3->archive_fd);

    fseek (is3->archive_fd, 4, SEEK_CUR);
    fread ((void*) (&(file->datetime) + 2), sizeof(uint16_t), 1, is3->archive_fd);
    fread ((void*)  &(file->datetime),      sizeof(uint16_t), 1, is3->archive_fd);

    fseek (is3->archive_fd, 4, SEEK_CUR);
    fread ((void*) &(chksize), sizeof(uint16_t), 1, is3->archive_fd);

    fseek (is3->archive_fd, 4, SEEK_CUR);
    fread ((void*) &(namelen), sizeof(uint8_t), 1, is3->archive_fd);

    //read in file name, ensure null termination;
    uint8_t buffer[namelen + 1];
    fread ((void*) buffer, sizeof(uint8_t), namelen, is3->archive_fd);
    buffer[namelen] = '\0';
    file->name = strdup ((char*) buffer);

    //complete out file entry with the offset within the body.
    file->offset = is3->datasize;
    
    if (!is3->files) {
        is3->files = file;
    } else {
       // append
       for (it = is3->files; it->next; it = it->next) { }
       it->next = file;
    }

    //increase body size to next offset for next file
    is3->datasize += file->compressed_size;
    
    //skip to end of chunk
    fseek (is3->archive_fd, chksize - namelen - 30, SEEK_CUR);
}


static bool extractFile (ishield3 * is3, const char *find_filestr, is3_file * selected_file, const char *outdir)
{
    //C style IO here because its easier to make work with Blast
    is3_file * file;
    FILE* ifh;
    FILE* ofh;
    struct utimbuf tstamp;

    if (selected_file) {
        file = selected_file;
    } else if (find_filestr) {
        /// file = is3->files.find(filename); 
        // TODO
    }

    size_t of_size = strlen(outdir) + strlen(file->name) + 50;
    char * of_name = (char*) malloc (of_size + 50);
    snprintf (of_name, of_size-2, "%s%c%s", outdir, DIR_SEPARATOR, file->name);

    ifh = fopen (is3->archive_fname, "rb");
    ofh = fopen (of_name, "wb");
    
    if (!ifh || !ofh) {
       return false;
    }
    
    fseek (ifh, file->offset + is3->dataoffset, SEEK_SET);
    
    blast(inf, ifh, outf, ofh, NULL, NULL);
    
    fclose(ifh);
    fclose(ofh);
    
    tstamp.actime = dos2unixtime (file->datetime);
    tstamp.modtime = tstamp.actime;
    utime (of_name, &tstamp);
    
    return true;
}


bool ishield3_extractAll (ishield3 * is3, const char *outdir)
{
    bool rv = true;
    is3_file * it = is3->files;
    
    while (it)
    {
        if(!extractFile (is3, NULL, it, outdir)) {
            rv = false;
        }
        it = it->next;
    }
    return rv;
}


void ishield3_listFiles (ishield3 * is3)
{
    const char * fname;
    //uint32_t size;
    uint32_t csize;
    time_t time;
    is3_file * it = is3->files;
    
    printf ("Archive contains the following files: \n");

    while (it)
    {
        time = dos2unixtime(it->datetime);
        fname = it->name;
        //size = it->uncompressed_size;
        csize = it->compressed_size;
        
        printf ("%s %u %s\n", fname, csize, ctime(&time));
        
        it = it->next;
    }
}
