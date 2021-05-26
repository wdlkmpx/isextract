#include <stdio.h>
#include <stdlib.h>
#include <utime.h>
#include <string.h>
#include <time.h>

#include "isextract.h"
#include "dostime.h"

typedef struct _is3_dir is3_dir;
struct _is3_dir {
    uint32_t count;
    is3_dir * next;
};


const uint32_t signature = 0x8C655D13;
const int32_t data_start = 255;
const uint32_t CHUNK = 16384;
/*const uint32_t YR_MASK  = 0xFE000000;
const uint32_t MON_MASK = 0x01E00000;
const uint32_t DAY_MASK = 0x001F0000;
const uint32_t HR_MASK  = 0x0000F800;
const uint32_t MIN_MASK = 0x000007E0;
const uint32_t SEC_MASK = 0x0000001F;*/

unsigned inf(void *how, unsigned char **buf)
{
    static unsigned char hold[CHUNK];

    *buf = hold;
    return fread(hold, 1, CHUNK, (FILE *)how);
}

int outf(void *how, unsigned char *buf, unsigned len)
{
    return fwrite(buf, 1, len, (FILE *)how) != len;
}

InstallShield::~InstallShield()
{
    close ();
}

InstallShield::InstallShield():
m_dataoffset(data_start),
m_datasize(0)
{
    m_files = NULL;
    m_filename = NULL;
}

void InstallShield::open(const char * filename)
{
    uint32_t sig;
    int32_t toc_address;
    uint16_t dir_count;

    m_filename = NULL;
    if (filename) {
        m_filename = strdup (filename);
    }
    
    file_handle = fopen (m_filename, "rb");
    
    if (!file_handle)
        throw "Could not open file.";

    fread (&sig, sizeof(uint32_t), 1, file_handle);
    
    //test if we have what we think we have
    if(sig != signature)
        throw "Not a valid InstallShield 3 archive.";
    
    //get some basic info on where stuff is in file
    fseek (file_handle, 37, SEEK_CUR);
    fread ((void*) &toc_address, sizeof(int32_t), 1, file_handle);

    fseek (file_handle, 4, SEEK_CUR);
    fread ((void*) &dir_count, sizeof(uint16_t), 1, file_handle);

    //find the toc and work out how many files we have in the archive
    fseek (file_handle, toc_address, SEEK_SET);

    is3_dir * dirfiles = NULL;
    is3_dir * currentdir = NULL, * dirtemp = NULL;

    for(uint32_t i = 0; i < dir_count; i++)
    {
        dirtemp = (is3_dir*) calloc (1, sizeof(is3_dir));
        dirtemp->count = parseDirs();
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
            parseFiles();
        }
        dirtemp = currentdir->next;
        free (currentdir);
        currentdir = dirtemp;
    }

    fclose (file_handle);
}

void InstallShield::close()
{
    // free data
    if (m_filename) {
        free (m_filename);
        m_filename = NULL;
    }
    if (m_files) {
       is3_file * it = m_files, * nextfile;
       while (it)
       {
           nextfile = it->next;
           if (it->name) free (it->name);
           free (it);
           it = nextfile;
       } 
    }
}

uint32_t InstallShield::parseDirs()
{
    uint16_t fcount;
    uint16_t chksize;
    uint16_t nlen;
    
    fread ((void*) &fcount,  sizeof(uint16_t), 1, file_handle);
    fread ((void*) &chksize, sizeof(uint16_t), 1, file_handle);
    fread ((void*) &nlen,    sizeof(uint16_t), 1, file_handle);

    printf ("We have %u files\n", fcount);
    
    //skip the name of the dir, we just want the files
    fseek (file_handle, nlen, SEEK_CUR);
    
    //skip to end of chunk
    fseek (file_handle, chksize - nlen - 6, SEEK_CUR);

    return fcount;
}

//uint AccumulatedData = 0;
void InstallShield::parseFiles()
{
    is3_file * file = (is3_file*) calloc (1, sizeof(is3_file));
    is3_file * it;
    uint16_t chksize;
    uint8_t namelen;

    fseek (file_handle, 3, SEEK_CUR);
    fread ((void*) &(file->uncompressed_size), sizeof(uint32_t), 1, file_handle);
    fread ((void*) &(file->compressed_size),   sizeof(uint32_t), 1, file_handle);

    fseek (file_handle, 4, SEEK_CUR);
    fread ((void*) (&(file->datetime) + 2), sizeof(uint16_t), 1, file_handle);
    fread ((void*)  &(file->datetime),      sizeof(uint16_t), 1, file_handle);

    fseek (file_handle, 4, SEEK_CUR);
    fread ((void*) &(chksize), sizeof(uint16_t), 1, file_handle);

    fseek (file_handle, 4, SEEK_CUR);
    fread ((void*) &(namelen), sizeof(uint8_t), 1, file_handle);

    //read in file name, ensure null termination;
    uint8_t buffer[namelen + 1];
    fread ((void*) buffer, sizeof(uint8_t), namelen, file_handle);
    buffer[namelen] = '\0';
    file->name = strdup ((char*) buffer);

    //complete out file entry with the offset within the body.
    file->offset = m_datasize;
    
    if (!m_files) {
        m_files = file;
    } else {
       // append
       for (it = m_files; it->next; it = it->next) { }
       it->next = file;
    }

    //increase body size to next offset for next file
    m_datasize += file->compressed_size;
    
    //skip to end of chunk
    fseek (file_handle, chksize - namelen - 30, SEEK_CUR);
}

bool InstallShield::extractFile (const char *find_filestr, is3_file * selected_file, const char *outdir)
{
    //C style IO here because its easier to make work with Blast
    is3_file * file;
    FILE* ifh;
    FILE* ofh;
    struct utimbuf tstamp;

    if (selected_file) {
        file = selected_file;
    } else if (find_filestr) {
        /// m_current_file = m_files.find(filename); 
        /// if(m_current_file != m_files.end()) {
        ///     file = *m_current_file;
        /// } else {
        ///     return false;
        /// }
        // TODO
    }

    m_current_file = file;

    size_t of_size = strlen(outdir) + strlen(file->name) + 50;
    char * of_name = (char*) malloc (of_size + 50);
    snprintf (of_name, of_size-2, "%s%c%s", outdir, DIR_SEPARATOR, file->name);

    ifh = fopen (m_filename, "rb");
    ofh = fopen (of_name, "wb");
    
    if (!ifh || !ofh) {
       return false;
    }
    
    fseek(ifh, m_current_file->offset + m_dataoffset, SEEK_SET);
    
    blast(inf, ifh, outf, ofh, NULL, NULL);
    
    fclose(ifh);
    fclose(ofh);
    
    tstamp.actime = dos2unixtime(m_current_file->datetime);
    tstamp.modtime = tstamp.actime;
    utime (of_name, &tstamp);
    
    return true;
}

bool InstallShield::extractAll(const char *outdir)
{
    bool rv = true;
    is3_file * it = m_files;
    
    while (it)
    {
        if(!extractFile (NULL, it, outdir)) {
            rv = false;
        }
        it = it->next;
    }
    return rv;
}

void InstallShield::listFiles()
{
    const char * fname;
    uint32_t size;
    uint32_t csize;
    time_t time;
    is3_file * it = m_files;
    
    printf ("Archive contains the following files: \n");

    while (it)
    {
        time = dos2unixtime(it->datetime);
        fname = it->name;
        size = it->uncompressed_size;
        csize = it->compressed_size;
        
        printf ("%s %u %s\n", fname, csize, ctime(&time));
        
        it = it->next;
    }
}
