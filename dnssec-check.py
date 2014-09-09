#!/usr/bin/python
# -*- coding: utf-8 -*-

### todo : TIMEZONE UTC bei RRSIG checks

import ldns
import sys
import re
from datetime import timedelta, datetime

rcodes = {0: "NoError",
          1: "FormErr",
          2: "ServFailServer",
          3: "NXDomain",
          4: "NotImp",
          5: "Refused", 
          6: "YXDomain",
          7: "YXRRSet", 
          8: "NXRRSet", 
          9: "NotAuth",
          10: "NotZone", 
          16: "BADVERS",
          16: "BADSIG",
          17: "BADKEY",
          18: "BADTIME",
          19: "BADMODE",
          20: "BADNAME",
          21: "BADALG", 
          22: "BADTRUNC"}

def check_name(name, rrtype):
   # Resolve IPv4 DNS name
   r = ldns.ldns_rr.new_frm_str(name + " A 1.2.3.4")
   r.set_type(rrtype)
   typestr = r.get_type_str()
   pkt = resolver.query(name, rrtype, ldns.LDNS_RR_CLASS_IN)
   if pkt and pkt.answer():
      for rr in pkt.answer().rrs():
         if (rr.get_type() == ldns.LDNS_RR_TYPE_RRSIG):
            rrsig =  { 'sig': str(rr.pop_rdf()), 'apex': str(rr.pop_rdf()), 'keyid': str(rr.pop_rdf()), 'inception': str(rr.pop_rdf()), 'expire': str(rr.pop_rdf()) }
            rrsigs[name+"::"+typestr] = rrsig

      # SERVFAIL indicated bogus name
      if pkt.get_rcode() is ldns.LDNS_RCODE_SERVFAIL:
         dnssec_state = " is bogus"
         bogusrr = True

      # Check AD (Authenticated) bit
      if pkt.get_rcode() is ldns.LDNS_RCODE_NOERROR:
         if pkt.ad(): dnssec_state = " is secure"
         else:        
            dnssec_state = " is insecure"
            insecurerr = True

      if pkt.ad():
         ad_flag = True
      if debug:
         print name + dnssec_state, "\t" + typestr + "-Record returned (" + str(pkt.ancount()) + " Records) RCODE:", rcodes[pkt.get_rcode()], "(AD: %d)" % ( pkt.ad() )

   else:
      print "No " + typestr +"-Record found", pkt.get_rcode()
      sys.exit(201)

def check_tlsa(tlsaname):
   tlsarr = resolver.query(tlsaname, ldns.LDNS_RR_TYPE_TLSA, ldns.LDNS_RR_CLASS_IN, ldns.LDNS_RD)
   if (tlsarr):
      for rr in tlsarr.answer().rrs():
         if (rr.get_type() == ldns.LDNS_RR_TYPE_RRSIG):
            rrsig =  { 'sig': str(rr.pop_rdf()), 'apex': str(rr.pop_rdf()), 'keyid': str(rr.pop_rdf()), 'inception': str(rr.pop_rdf()), 'expire': str(rr.pop_rdf()) }
            rrsigs[tlsaname+'::TLSA'] = rrsig
         if (rr.get_type() == ldns.LDNS_RR_TYPE_TLSA):
            tlsas[tlsaname] = rr

debug = True
rrsigs = {}
tlsas = {}
ds_keyid = 0

# Flags for DNSSEC checks
ds_found = False
zsk_found = False
ksk_found = False
ad_flag = False
ds_key_match = False
bogusrr = False
insecurerr = False

# signature validity
mindelta = 60*60*24*30 # 30 days
rrsig_thresold = 60*60*24*3 # 3 days

# Check args
argc = len(sys.argv)
name = "sys4.de"

if argc < 2:
   print "Usage:", sys.argv[0], "domain [resolver_addr]"
   sys.exit(1)
else:
   name = sys.argv[1]

if debug:
   print "Checking domain:\t" + name
   print "----------------"

# Create resolver
resolver = ldns.ldns_resolver.new_frm_file("/etc/resolv.conf")
resolver.set_dnssec(True)

# Custom resolver
if argc > 2:
   # Clear previous nameservers
   ns = resolver.pop_nameserver()
   while ns != None:
      ns = resolver.pop_nameserver()
   ip = ldns.ldns_rdf.new_frm_str(sys.argv[2], ldns.LDNS_RDF_TYPE_A)
   resolver.push_nameserver(ip)


check_name(name, ldns.LDNS_RR_TYPE_A)
check_name(name, ldns.LDNS_RR_TYPE_AAAA)
check_tlsa("_443._tcp." + name)
check_name("www."+name, ldns.LDNS_RR_TYPE_A)
check_name("www."+name, ldns.LDNS_RR_TYPE_AAAA)
check_tlsa("_443._tcp.www." + name)

## Resolve DS-Record
dsrr = resolver.query(name, ldns.LDNS_RR_TYPE_DS,  ldns.LDNS_RR_CLASS_IN)
if (dsrr) and (dsrr.answer()):
    for rr in dsrr.answer().rrs():
        if (rr.get_type() != ldns.LDNS_RR_TYPE_DS):
            continue
        if (rr.get_type() == ldns.LDNS_RR_TYPE_DS):
           ds_hash = rr.pop_rdf()
           ds_hashalgo = rr.pop_rdf()
           ds_keyalgo = rr.pop_rdf()
           ds_keyid = rr.pop_rdf()
           ds_found = True

dnskey = resolver.query(name, ldns.LDNS_RR_TYPE_DNSKEY,  ldns.LDNS_RR_CLASS_IN)
if (dnskey) and (dnskey.answer()):

    for rr in dnskey.answer().rrs():
        if (rr.get_type() == ldns.LDNS_RR_TYPE_RRSIG):
           rrsig =  { 'sig': str(rr.pop_rdf()), 'apex': str(rr.pop_rdf()), 'keyid': str(rr.pop_rdf()), 'inception': str(rr.pop_rdf()), 'expire': str(rr.pop_rdf()) }
           rrsigs[name+'::DNSKEY'] = rrsig

        if (rr.get_type() != ldns.LDNS_RR_TYPE_DNSKEY):
            continue

        rrstr = ldns.ldns_rr2str(rr)
        regex = re.compile("\;\{id = (\d{1,5}) .*")
        keyid = regex.findall(rrstr)[0]
        flags = str(rr.dnskey_flags())
	if flags == "256":
           if debug:
              print "Got ZSK"
           zsk_found = True
           dnskey_zsk = rr.dnskey_key()
	if flags == "257":
           if debug:
              print "Got KSK"
           ksk_found = True
           dnskey_ksk = rr.dnskey_key()
           if (keyid == str(ds_keyid)):
              ds_key_match = True;
              if debug:
                 print "DS Key-ID matches KSK-Key-ID"

mxrr = resolver.query(name, ldns.LDNS_RR_TYPE_MX, ldns.LDNS_RR_CLASS_IN, ldns.LDNS_RD)
if (mxrr):
    for rr in mxrr.answer().rrs():
        if (rr.get_type() == ldns.LDNS_RR_TYPE_RRSIG):
           rrsig =  { 'sig': str(rr.pop_rdf()), 'apex': str(rr.pop_rdf()), 'keyid': str(rr.pop_rdf()), 'inception': str(rr.pop_rdf()), 'expire': str(rr.pop_rdf()) }
           rrsigs[name+'::MX'] = rrsig

        if (rr.get_type() != ldns.LDNS_RR_TYPE_MX):
            continue

	mailhost = str(rr.pop_rdf())
	if debug:
           print "Mailhost: " + mailhost
        tlsaname = "_25._tcp." + mailhost
        check_tlsa(tlsaname)

## check RRSIG expiry
if debug:
   print "RRSIG expire values:"

for rrtype, sigdata in rrsigs.iteritems():
   datenow = datetime.now()
   expire = datetime.strptime(sigdata['expire'], '%Y%m%d%H%M%S')
   inception = datetime.strptime(sigdata['inception'], '%Y%m%d%H%M%S')
   delta = expire - datenow

   if mindelta > delta.total_seconds():
      mindelta = delta.total_seconds()

   if debug:
      print "> " + rrtype.ljust(40) + "\t valid from " + str(inception) + " to " + str(expire) + " for " + str(delta)

## print TLSA Records found
if debug:
   print "TLSA-Records:"

for name, tlsa in tlsas.iteritems():
   if debug:
      print "TLSA -> " + str(tlsa)

if not ds_found:
   if debug:
      print "ERROR: No DS-Record found"
   sys.exit(210)

if not ksk_found:
   if debug:
      print "ERROR: No KSK-Record found"
   sys.exit(211)

if not zsk_found:
   if debug:
      print "ERROR: No ZSK-Record found"
   sys.exit(212)

if ad_flag:
   if debug:
      print "ERROR: No AD-Flag on A/AAAA responses"
   sys.exit(213)

if insecurerr:
   if debug:
      print "ERROR: insecure answer recieved"
   sys.exit(214)

if bogusrr:
   if debug:
      print "ERROR: received BOGUS (invalid DNSSEC data) response"
   sys.exit(215)

if not ds_key_match:
   if debug:
      print "ERROR: DS Ket-ID KSK mismatch"
   sys.exit(217)

if (mindelta < rrsig_thresold):
   if debug:
      print "ERROR: RRSIGS past expiry threshold"
   sys.exit(216)
