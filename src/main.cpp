#include <stdio.h>
#include <stdlib.h>
#include <iostream>

#include "isextract.h"

void printUse()
{
    std::cout << "Useage is \"isextract [mode] [file] (dir)\"\n"
              << "mode options are \'x\' for extract and \'l\' for list.\n";
}

int main(int argc, char** argv)
{
    std::string mode;
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
        std::cout << "Error opening file\n";
        return -1;
    }
    
    if(mode == "x"){
        ishield3_extractAll (infile, outdir);
    } else if(mode == "l") {
        ishield3_listFiles (infile);
    } else {
        printUse();
    }

    ishield3_close (infile);
    infile = NULL;
    
    return 0;
}
