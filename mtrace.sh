#!/bin/sh
# This is free and unencumbered software released into the public domain.
#  For more information, please refer to <https://unlicense.org>

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
