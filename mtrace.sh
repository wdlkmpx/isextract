#!/bin/sh
# This file is put in the public domain

#-------------------
app="build/isextract"
#-------------------

export MALLOC_TRACE=$(pwd)/mtrace.txt

rm -f ${app}

if test -f Makefile ; then
	make clean
	make OPTFLAGS="-DDEBUG -ggdb3"
fi

mtrace=
for i in $(echo $PATH | tr ':' ' ')
do
	if test -x $i/mtrace ; then
		mtrace=$i/mtrace;
		break;
	fi
done

${app} x test/DATA.Z test

if test "x${mtrace}" != "x" ; then
	mtrace ${app} mtrace.txt > mtrace-out.txt;
	printf "see mtrace-out.txt\n";
else
	printf "mtrace is missing\n";
	printf "see mtrace.txt\n"
fi
