#include <stdio.h>
#include <stdlib.h>

#include "isextract.h"

void printUse()
{
    puts ("Useage is \"isextract [mode] [file] (dir)\"\n");
    puts ("mode options are \'x\' for extract and \'l\' for list.\n");
}

int main(int argc, char** argv)
{
    const char * mode;
    const char * filepath;
    const char * outdir = "./";
    ishield3 * infile;
    
    if(argc < 3) {
        printUse();
        return 0;
    }
    
    mode = argv[1];
    filepath = argv[2];
    
    if(argc >= 4) {
        outdir = argv[3];
    }
    
    infile = ishield3_open (filepath);
    if (!infile) {
        puts ("Error opening file\n");
        return -1;
    }
    
    if(*mode == 'x'){
        ishield3_extractAll (infile, outdir);
    } else if(*mode == 'l') {
        ishield3_listFiles (infile);
    } else {
        printUse();
    }

    ishield3_close (infile);
    infile = NULL;
    
    return 0;
}
