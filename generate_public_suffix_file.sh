DATA=`curl http://mxr.mozilla.org/mozilla-central/source/netwerk/dns/effective_tld_names.dat?raw=1 |
perl -i -pe 's/(^\/\/.*\n|^\s*\n)//g'|
perl -i -pe 's/^/"/'| perl -i -pe 's/$/",/'`
DATA="var public_suffix_list = [$DATA];"
LINE=`grep -n 'PUBLIC SUFFIX LIST' publicsuffix.js.orig |cut -d : -f 1`
head -n $LINE publicsuffix.js.orig > publicsuffix.js
echo $DATA >> publicsuffix.js
tail -n +$(($LINE+1)) publicsuffix.js.orig >> publicsuffix.js
