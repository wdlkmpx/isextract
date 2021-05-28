#include <stdio.h>
#include <time.h>
#include <stdlib.h>
#include <utime.h>
#include <string.h>
#include <stdint.h>

#include <sys/stat.h>

#include "isextract.h"
#include "dostime.h"


#ifdef _WIN32
#define DIR_SEPARATOR '\\'
#include "win32/stdint.h"
#else
#define DIR_SEPARATOR '/'
#include <stdint.h>
#endif

const uint32_t signature32 = 0x8C655D13;
/* Files begin with bytes 13 5D 65 8C 3A 01 02 00 */
const uint8_t signature[8] = { 0x13, 0x5D, 0x65, 0x8C, 0x3A, 0x01, 0x02, 0x00 };
const int32_t data_start = 255;
#define CHUNK 16384

// =================================================================

typedef struct _is3_dir is3_dir;
struct _is3_dir {
    uint32_t file_count;
    char * name;
};


typedef struct _is3_file is3_file;
struct _is3_file
{
    char * name;
    uint32_t compressed_size;
    uint32_t uncompressed_size;
    uint32_t offset;
    uint32_t datetime;
    is3_dir  * parentdir;
    is3_file * next;
};


typedef struct __attribute__((__packed__)) _is3_header
{
    uint8_t signature[8];
    /* */ uint8_t ignore0[4];
    uint16_t file_count;
    /* */ uint8_t ignore1[4];
    uint32_t archive_size;
    /* */ uint8_t ignore2[19];
    uint32_t toc_address;
    /* */ uint8_t ignore3[4];
    uint16_t dir_count;
} is3_header;


struct _ishield3
{
    is3_dir  * directories;
    is3_file * files;
    char * archive_fname;
    FILE * archive_fd;
    uint32_t dataoffset;
    uint32_t datasize;
    is3_header header;
};

// =================================================================

static void parseDirs  (ishield3 * is3, is3_dir * dir);
static void parseFiles (ishield3 * is3, is3_dir * dir);
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
    FILE * fd;
    size_t read_bytes;

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

    //get some basic info on where stuff is in file
    read_bytes = fread (&(is3->header), 1, sizeof(is3->header), is3->archive_fd);
    if (read_bytes < sizeof(is3->header))
    {
       fprintf (stderr, "Error reading %s\n", filename);
       ishield3_close (is3);
       return NULL;
    }
    
    //test if we have what we think we have
    if (memcmp (is3->header.signature, signature, sizeof(signature)) != 0) {
        fprintf (stderr, "Not a valid InstallShield 3 archive\n");
        ishield3_close (is3);
        return NULL;
    }

    //find the toc and work out how many files we have in the archive
    fseek (is3->archive_fd, is3->header.toc_address, SEEK_SET);

    is3->directories = (is3_dir *) malloc (is3->header.dir_count * sizeof(is3_dir));

    for (uint32_t i = 0; i < is3->header.dir_count; i++)
    {
        parseDirs (is3, &(is3->directories[i]));
    }

    //parse the file entries in the toc to get filenames, size and location
    for (uint32_t i = 0; i < is3->header.dir_count; i++)
    {
        for (uint32_t j = 0; j < is3->directories[i].file_count; j++) {
            parseFiles (is3, &(is3->directories[i]));
        }
    }

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
       is3->files = NULL;
    }
    if (is3->directories) {
       for (uint32_t i = 0; i < is3->header.dir_count; i++) {
           if (is3->directories[i].name)
               free (is3->directories[i].name);
       }
       free (is3->directories);
       is3->directories = NULL;
    }
    if (is3->archive_fd) {
       fclose (is3->archive_fd);
    }
    if (is3) {
       free (is3);
    }
}


static void parseDirs  (ishield3 * is3, is3_dir * dir)
{
    uint16_t fcount;
    uint16_t chksize;
    uint16_t nlen;

    fread ((void*) &fcount,  sizeof(uint16_t), 1, is3->archive_fd);
    fread ((void*) &chksize, sizeof(uint16_t), 1, is3->archive_fd);
    fread ((void*) &nlen,    sizeof(uint16_t), 1, is3->archive_fd);

    dir->name = (char *) malloc (sizeof(uint8_t) * nlen + 3);
    dir->name[nlen] = 0;
    fread ((void*) dir->name, sizeof(uint8_t), nlen, is3->archive_fd);
    
    //skip to end of chunk
    fseek (is3->archive_fd, chksize - nlen - 6, SEEK_CUR);

    dir->file_count = fcount;
    if (dir->name[0] == 0) {/* root dir */
        printf ("(Top dir): %u files\n", dir->file_count);
    } else {
        printf ("%s: %u files\n", dir->name, dir->file_count);
    }
}


static void parseFiles (ishield3 * is3, is3_dir * dir)
{
    is3_file * file = (is3_file*) calloc (1, sizeof(is3_file));
    is3_file * it;
    uint16_t chksize;
    uint16_t date1, date2;
    uint8_t namelen;

    fseek (is3->archive_fd, 3, SEEK_CUR);
    fread ((void*) &(file->uncompressed_size), sizeof(uint32_t), 1, is3->archive_fd);
    fread ((void*) &(file->compressed_size),   sizeof(uint32_t), 1, is3->archive_fd);

    fseek (is3->archive_fd, 4, SEEK_CUR);
    fread ((void*) &(date1), sizeof(uint16_t), 1, is3->archive_fd);
    fread ((void*) &(date2), sizeof(uint16_t), 1, is3->archive_fd);
    file->datetime = (date1 << 16) + date2;

    fseek (is3->archive_fd, 4, SEEK_CUR);
    fread ((void*) &(chksize), sizeof(uint16_t), 1, is3->archive_fd);

    fseek (is3->archive_fd, 4, SEEK_CUR);
    fread ((void*) &(namelen), sizeof(uint8_t), 1, is3->archive_fd);

    if (dir) {
        file->parentdir = dir;
    }

    //read in file name, ensure null termination;
    file->name = (char *) malloc (sizeof(uint8_t) * namelen + 3);
    file->name[namelen] = 0;
    fread ((void*) file->name, sizeof(uint8_t), namelen, is3->archive_fd);

    //complete out file entry with the offset within the body.
    file->offset = is3->datasize;

    file->next = NULL;
    if (!is3->files) {
        is3->files = file; /* first file */
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
    int extractdirs = 1; //change to 0 to test without directories
    is3_file * file;
    FILE* ifh = is3->archive_fd;
    FILE* ofh;
    struct utimbuf tstamp;

    char * of_name, * of_dir, *p;
    size_t of_size;

    if (selected_file) {
        file = selected_file;
    } else if (find_filestr) {
        /// file = is3->files.find(filename); 
        // TODO
    }

    of_size = strlen(outdir) + strlen(file->parentdir->name) +
                     strlen(file->name) + 20;
    of_name = (char*) malloc (of_size);

    if (extractdirs && file->parentdir && file->parentdir->name[0])
    {
        snprintf (of_name, of_size-2, "%s%c%s%c%s",
                  outdir, DIR_SEPARATOR,
                  file->parentdir->name, DIR_SEPARATOR,
                  file->name);
#ifndef _WIN32
        // subdirecties contain '\': dir\subdir
        for (p = of_name; *p; p++) {
            if (*p == '\\') *p = '/';
        }
#endif
        // may need to create directory
        p = strrchr (of_name, DIR_SEPARATOR);
        *p = 0;
        of_dir = of_name;
        mkdir (of_dir, S_IRWXU | S_IRWXG | S_IROTH | S_IXOTH);
        *p = DIR_SEPARATOR;

    } else {
        snprintf (of_name, of_size-2, "%s%c%s",
                  outdir, DIR_SEPARATOR, file->name);
    }

    //ifh = fopen (is3->archive_fname, "rb");
    ofh = fopen (of_name, "wb");
    
    if (!ifh || !ofh) {
       return false;
    }
    
    fseek (ifh, file->offset + is3->dataoffset, SEEK_SET);
    
    blast(inf, ifh, outf, ofh, NULL, NULL);
    
    fclose(ofh);
    tstamp.actime = dos2unixtime (file->datetime);
    tstamp.modtime = tstamp.actime;
    utime (of_name, &tstamp);
    free (of_name);

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
    char timestr[256];
    
    printf ("Archive contains the following files: \n");

    while (it)
    {
        time = dos2unixtime(it->datetime);
        fname = it->name;
        //size = it->uncompressed_size;
        csize = it->compressed_size;
        strftime (timestr, sizeof(timestr)-1, // ctime(&time)
                  "%Y-%m-%d %H:%M:%S\n", localtime(&time));

        if (it->parentdir && it->parentdir->name[0]) {
            // ctime() adds a '\n'
            printf ("%s\\%s - %u - %s", it->parentdir->name, fname, csize, timestr);
        } else {
            printf ("%s - %u - %s", fname, csize, timestr);
        }
        it = it->next;
    }
}
