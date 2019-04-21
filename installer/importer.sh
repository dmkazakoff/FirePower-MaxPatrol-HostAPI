#!/bin/bash
for file in /Volume/home/admin/export/*.txt
do
  echo "Importing file $file"
  nmimport.pl "$file"
done
