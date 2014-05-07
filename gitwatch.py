#!/usr/bin/python

import urllib2
import json
import time
import MySQLdb
import logging
import sys
import ConfigParser
from datetime import datetime

#TODO: add cmdline parser for -c
configfile="gitwatch.conf"

# set up logging before parsing the rest of the config, so we can
# log config errors to file
try:
  p=ConfigParser.SafeConfigParser()
  p.read(configfile)

  logfilename=p.get("logging","filename")
  fileloglevel=p.get("logging","fileloglevel")
  consoleloglevel=p.get("logging","consoleloglevel")
except ConfigParser.Error, e:
  print "Error parsing logging settings from %s: %s" % (configfile,e)
  sys.exit(1)

fileloglevelnum=getattr(logging,fileloglevel.upper(),None)
consoleloglevelnum=getattr(logging,consoleloglevel.upper(),None)

if not isinstance(fileloglevelnum,int):
  raise ValueError("File log level invalid: %s" % fileloglevel)
if not isinstance(consoleloglevelnum,int):
  raise ValueError("Console log level invalid: %s" % consoleloglevel)

logging.basicConfig(
  level=fileloglevelnum,
  format='%(asctime)s %(levelname)s %(message)s',
  filename=logfilename,
  filemode='a')

console=logging.StreamHandler()
console.setLevel(consoleloglevelnum)
logging.getLogger('').addHandler(console)
logging.warn("GitWatch starting.")

# now we can parse the rest of the config
try:
  useragent=p.get("api","useragent")
  urlproto=p.get("api","urlproto")
  sleepinterval=int(p.get("api","defaultinterval"))

  dbhost=p.get("database","dbhost")
  dbuser=p.get("database","dbuser")
  dbpass=p.get("database","dbpass")
  dbname=p.get("database","dbname")

  ircchan=p.get("irc","channel").replace('#','') # remove '#' if present
  ircchan=MySQLdb.escape_string(ircchan)
  maxlinelen=p.get("irc","maxlinelen")
except ConfigParser.Error, e: 
  logging.critical("Error parsing %s: %s" % (configfile,e))
  sys.exit(1)

try:
  dbcon=MySQLdb.connect(host=dbhost,user=dbuser,passwd=dbpass,db=dbname)
except MySQLdb.Error, e:
  logging.critical("Error %d connecting to mysql: %s" % (e.args[0],e.args[1]))
  sys.exit(1)
logging.info("Connected successfully to MySQL")

class user:
  def __init__(self,username):
    self.username=username
    self.etag=None
    self.lastts=int(datetime.utcnow().strftime("%s"))    

    logging.info("Added user %s" % username)
  def update(self):
    logging.debug("Updating %s" % self.username)

    url=urlproto.replace(':user',self.username)
    headers={'User-Agent':useragent}
    if self.etag is not None:
      headers['If-None-Match']=self.etag

    req=urllib2.Request(url,None,headers)
    
    try:
      resp=urllib2.urlopen(req,None,10)
    except urllib2.HTTPError, e:
      if str(e)=='HTTP Error 304: Not Modified':
        logging.debug("304: Nothing new for %s" % self.username)
      else:
        logging.error("HTTP Error on %s: %s" % (self.username,e))

      return
    except Exception, e:
      logging.error("Error fetching api for %s: %s" % (self.username,e))
      return

    self.etag=resp.headers.getheader('etag')

    # we could do a smarter adaptive strategy for the quickest possible
    # update times, but a minute or two of latency doesnt matter much.
    # also of note: when passing an etag and receiving 304, the request
    # does not count against the ratelimit. since a very small ratio of 
    # watched accounts actually have updates each time, this means we dont
    # need to multiple by the number of followed users.
    potentialival=2*int(resp.headers.getheader('x-poll-interval'))

    if sleepinterval!=potentialival:
      logging.warn("Changing sleep interval from %d to %d." % (
        sleepinterval,potentialival))
      setsleepint(potentialival) # see note on func about scope

    if 0==int(resp.headers.getheader('x-ratelimit-remaining')):
      logging.error("API ratelimit exceeded!")

    data=resp.read()
    try:
      items=json.loads(data)
    except Exception, e:
      logging.error("Error parsing json for %s: %s" % (self.username,e))
      return

    logging.debug("%d items returned for %s" % (len(items),self.username))

    # ts is used to determine new events, since etags only trigger a paginated return
    maxts=self.lastts
    for i in items:
      thists=int(datetime.strptime(i['created_at'],"%Y-%m-%dT%H:%M:%SZ").strftime("%s"))

      # if this item happened before the last update for this user, dont bother with it
      if thists<self.lastts: 
        logging.debug("Skipping %s on %s since time %d is behind %d" % (
          i['type'],i['repo']['name'],thists,self.lastts))
        continue

      # items dont always arrive in time order, so we have to set this after iteration
      if thists>maxts: maxts=thists 

      if i['type']=='PushEvent':
        if i['payload'].has_key('commits'):
          for c in i['payload']['commits']: 
            sendmessage("Commit to %s by %s: %s" % (
              i['repo']['name'],c['author']['name'],c['message']))
        else:
          logging.warn("!!! PushEvent with no commits on %s! " % i['repo']['name'])

      elif i['type']=='CreateEvent':
        if i['payload']['ref_type']=='repository':
          sendmessage("Repo %s created by %s" % (i['repo']['name'],i['actor']['login']))
        else:
          sendmessage("%s created %s %s on %s" % (
            i['actor']['login'],i['payload']['ref_type'],
            i['payload']['ref'],i['repo']['name']))

      elif i['type']=='IssueCommentEvent':
        buf="Comment on %s by %s:" % (i['repo']['name'],i['actor']['login'])
        bodylen=maxlinelen-(len(buf)+len(i['payload']['issue']['html_url'])+4)
        body=i['payload']['issue']['body'];
        body=body.replace('\r','')
        body=body.replace('\n',' ')
        body=body.replace('![image]','')

        if bodylen<len(body):
          body="%s..." % body[:bodylen-3]

        sendmessage("%s %s (%s)" % (buf,body,i['payload']['issue']['html_url']))

      elif i['type']=="IssuesEvent":
        buf="%s %s an issue on %s:" % (i['actor']['login'],
          i['payload']['action'],i['repo']['name'])
        bodylen=maxlinelen-(len(buf)+len(i['payload']['issue']['html_url'])+4)
        body=i['payload']['issue']['body'];
        body=body.replace('\r','')
        body=body.replace('\n',' ')
        body=body.replace('![image]','')

        if bodylen<len(body):
          body="%s..." % body[:bodylen-3]

        sendmessage("%s %s (%s)" % (buf,body,i['payload']['issue']['html_url']))

      elif i['type']=='ForkEvent':
        sendmessage("%s forked %s to %s!" % (i['actor']['login'],i['repo']['name'],
          i['payload']['forkee']['full_name']))

      elif i['type']=='PublicEvent':
        sendmessage("%s set %s from private to public!" % (
          i['actor']['login'],i['repo']['name']))

      elif i['type']=='WatchEvent':
        sendmessage("%s is now watching %s" % (i['actor']['login'],i['repo']['name']))

      # there are several other EventTypes that I haven't implemented here,
      # see https://developer.github.com/v3/activity/events/types/
      # (may do them in the future if there's need, but the ones we care most
      # about are covered)
      else:
        logging.warn("Unimplemented EventType to %s: %s" % (i['repo']['name'],i['type']))

    self.lastts=maxts

# the current IRC bot we use nabs from a db table queue via http api, but really
# should be moved to zmq.
def sendmessage(msg):
  logging.debug("Sending message: %s" % msg)

  # we throw away non-ascii chars since the ircd doesnt like them. if yours handles
  # unicode properly, you can remove this
  msg=msg.decode('ascii','ignore') 

  sql="INSERT INTO irc_sendq(ts,sent,channel,txt) VALUES "
  sql+="(UNIX_TIMESTAMP(),0,'%s','%s')" % (ircchan,MySQLdb.escape_string(msg))

  try:
    dbcon.ping(True) # reconnect if we have timed out
    dbc=dbcon.cursor()
    dbc.execute(sql)
  except Exception, e:
    logging.error("Error inserting into DB: %s" % e)

# this wrapper is needed since we cant assign directly to sleepinterval
# from within the class method (ugly, should be cleaned up)
def setsleepint(s):
  sleepinterval=s

def main():
  # if it turns out to be useful, we can parse out specific EventTypes per-user
  # here, but currently the value is ignored.
  users=map(user,p.options("users"))

  while True:
    [u.update() for u in users]
    time.sleep(sleepinterval)

if __name__ == '__main__': main()
# could make this a nicer daemon if need be:
# - sigterm and sigint handlers
# - dynamic conf reloading
# - put the whole thing in a loadable module

