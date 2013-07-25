echo "var public_suffix_list = [" > publicsuffix.json
curl http://mxr.mozilla.org/mozilla-central/source/netwerk/dns/effective_tld_names.dat?raw=1 |
perl -i -pe 's/(^\/\/.*\n|^\s*\n)//g'|
perl -i -pe 's/^/"/'|
perl -i -pe 's/$/",/' >> publicsuffix.json
echo "];" >> publicsuffix.json
