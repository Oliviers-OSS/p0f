/*
 
  p0f - passive OS fingerprinting
  -------------------------------
  (c) <lcamtuf@tpi.pl>
  
  The p0f utility and related utilities are free software; you can
  redistribute it and/or modify it under the terms of the GNU Library
  General Public License as published by the Free Software Foundation;
  either version 2 of the License, or (at your option) any later version.
	  
  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS
  OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL
  MICHAL ZALEWSKI, OR ANY OTHER CONTRIBUTORS BE LIABLE FOR ANY CLAIM,
  DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
  OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE
  OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
			
*/

#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <pcap.h>
#include <arpa/inet.h>
#include <signal.h>
#include <unistd.h>

#include "tcp.h"
#define MAXFPS 1000
#define FPBUF  120
#define INBUF  1024
#define TTLDW  30

#ifndef VER
#  define VER "(?)"
#endif /* !VER */

extern char *optarg;
extern int optind;

char fps[MAXFPS][FPBUF];
int wss, wscale, mss, nop, ttl, df, sok,tmp,header_len=14,dupa;
int verbose=0,sp,dp;
struct in_addr sip,dip;
struct bpf_program flt;
pcap_t *pt;

void die_nicely() {
  pcap_close(pt);
  exit(0);
}


void lookup(void);

void parse(u_char *blabla, struct pcap_pkthdr *pph, u_char *packet) {
  struct iphdr *iph;
  struct tcphdr *tcph;
  int ilen=0, hlen=0,off,olen;
  dupa=0;
  
  if (pph->len < header_len+sizeof(struct iphdr)+sizeof(struct tcphdr)) {
    return;
  }
  // Rare tropical disease ugly dirty obfuscated hack ;>
  iph=(struct iphdr*) (packet);
  if ((iph->ihl>>4)!=4 || iph->protocol!=IPPROTO_TCP)
    iph=(struct iphdr*)(packet+header_len);
  if ((iph->ihl>>4)!=4 || iph->protocol!=IPPROTO_TCP) {
    int a,b;
    iph=(struct iphdr*) (packet);
    // Change ihl byteorder, endian detection ;)
    a=iph->ihl&15;b=(iph->ihl>>4)&15;iph->ihl=a*16+b;
    if ((iph->ihl>>4)!=4 || iph->protocol!=IPPROTO_TCP)
      iph=(struct iphdr*)(packet+header_len);
    if ((iph->ihl>>4)!=4 || iph->protocol!=IPPROTO_TCP) {
      return;
    }
  }

  ttl=iph->ttl;

  off=ntohs(iph->off);
  df=((off&IP_DF)!=0);
  sip.s_addr=iph->saddr;
  dip.s_addr=iph->daddr;
  ilen= ( (iph->ihl&0x0f) );

  switch (ilen) {
    case 5: /* no options */
      tcph=(struct tcphdr *)(iph+1);
      break;
    default: /* parse ipoptions */
      if ((header_len+(ilen<<2)+sizeof(struct tcphdr)) > pph->len) {
	return;
      }
      tcph=(struct tcphdr *)(packet+header_len+(ilen<<2));
      break;
  }

  off=tcph->th_flags;
  if (!(off&TH_SYN)) return;
  if ((off&TH_ACK)) return;

  wscale=-1;
  mss=0;
  nop=0;
  sok=0;

  hlen=(tcph->th_off)*4;

  {
    void* opt_ptr;
    int opt;
    opt_ptr=(void*)tcph+sizeof(struct tcphdr);
    while (dupa<hlen) {
      opt=(int)(*(u_char*)(opt_ptr+dupa));
      dupa+=1;
      switch(opt) {
        case TCPOPT_EOL:
	  dupa=100000; break; // Abandon ship!
        case TCPOPT_NOP:
  	  nop=1;
	  break;
	case TCPOPT_SACKOK:
 	  sok=1;
	  dupa++;
	  break;
	// Long options....
	case TCPOPT_MAXSEG:
	  dupa++;
  	  mss=EXTRACT_16BITS(opt_ptr+dupa);
  	  dupa+=2;
	  break;
	case TCPOPT_WSCALE:
	  olen=(int)*((char*)opt_ptr+dupa)-2; dupa++;
	  if (olen<0) olen=0;
  	  wscale=(int)*((u_char*)opt_ptr+dupa);
	  dupa+=olen;
	  break;
	case TCPOPT_TIMESTAMP:
	  olen=(int)*((char*)opt_ptr+dupa)-2; dupa++;
	  if (olen<0) olen=0;
	  dupa+=olen;
	  break;
	default:
	  olen=(int)*((char*)opt_ptr+dupa)-2; dupa++;
	  if (olen<0) olen=0;
	  dupa+=olen;
	 break;
      }
    }
  }
#if BYTE_ORDER == LITTLE_ENDIAN
  sp=htons(tcph->th_sport);
  dp=htons(tcph->th_dport);
  wss=htons(tcph->th_win);
#else
  sp=tcph->th_sport;
  dp=tcph->th_dport;
  wss=tcph->th_win;
#endif
  lookup();
  return;
}


void lookup(void) {
  int i=0,got=0,down=0;
  int origw=wscale;
  char buf[INBUF],*p;
  char* plonked="\n";
plonk:
  for (down=0;down<TTLDW;down++) {
    i=0;
    sprintf(buf,"%d:%d:%d:%d:%d:%d:%d:",wss,ttl+down,mss,df,wscale,sok,nop);
    while (fps[i][0]) {
      if (!strncmp(buf, fps[i], strlen(buf))) {
        got=1;
        p=strrchr(fps[i],':')+1;
        if (strchr(p, '\n')) p[strlen(p)-1]=0;
        printf("%s [%d hops]: %s%s",inet_ntoa(sip),down+1,p,plonked);
	if (verbose) {
	  printf(" + %s:%d ->",inet_ntoa(sip),sp);
	  printf(" %s:%d\n", inet_ntoa(dip),dp);
	}
        break;
      }
      i++;
    }
    if (got) break;
  }
  if (!got) if (wscale==-1) { plonked=" *\n";wscale=0; goto plonk; }
  if (!got) printf("%s: UNKNOWN [%d:%d:%d:%d:%d:%d:%d].\n",
            inet_ntoa(sip), wss, ttl, mss, df, origw, sok, nop);
  fflush(0);
}

int fips;

void load_fprints(char *filename) {
  FILE *x;
  int i=0;
  char *p;
  x=fopen(filename, "r");
  if (!x) x=fopen("p0f.fp", "r");
  if (!x) {
    fprintf(stderr, "No OS fingerprint database (%s) found. Dumb mode on.\n", 
      filename);
    return;
  }
  while (fgets(fps[i],FPBUF-1,x)) {
    if ((p=strchr(fps[i],'#')))	*p=0;
    if (fps[i][0]) i++;
  }
  fips=i;
  fclose(x);
}

char *ifa,*rul;

void usage(char* what) {
  fprintf(stderr,"p0f: %s\n",what);
  fprintf(stderr,"usage: p0f [ -f file ] [ -i device ] [ -s file ] [ -v ][ 'filter rule' ]\n");
  fprintf(stderr, " -f file   read fingerprint information from file\n");
  fprintf(stderr, " -i device read packets from device\n");
  fprintf(stderr, " -s file   read packets from file\n");
  fprintf(stderr, " -v        verbose mode\n");
  exit(1);
}


int main(int argc, char *argv[]) {
  char errbuf[PCAP_ERRBUF_SIZE];
  char *filename = NULL, *inputfile = NULL;
  int r, s = 0;
  
  while ((r = getopt(argc, argv, "f:i:s:v")) != -1) {
    switch (r) {
      case 'f':
        filename = optarg;
	break;
      case 'i':
	ifa = optarg;
	break;
      case 's':
        s = 1;
	inputfile = optarg;
	break;
      case 'v':
        verbose = 1;
	break;
      default:
	usage("Unknown option.");
    }
  }

  /* set a reasonable default fingerprint file */
  if (!filename || !*filename)
    filename = "/etc/p0f.fp";

  /* anything left after getopt'ing is a rule */
  if (argv[optind] && *(argv[optind]))
    rul = argv[optind];
  
  if (!ifa) ifa=pcap_lookupdev(errbuf);
  if (!ifa) { ifa="lo"; }
  
  fprintf(stderr, "p0f: passive os fingerprinting ver. " VER " by <lcamtuf@tpi.pl>\n");
  
  if (s && inputfile && *inputfile) {
    if ((pt=pcap_open_offline(inputfile, errbuf))==NULL) {
      fprintf(stderr, "pcap_open_offline failed: %s\n", errbuf);
      exit(1);
    }
  } else {
    if ((pt=pcap_open_live(ifa,100,1,100,errbuf))==NULL) {
      fprintf(stderr, "pcap_open_live failed: %s\n", errbuf);
      exit(1);
    }
  }

  signal(SIGINT,&die_nicely);
  signal(SIGTERM,&die_nicely);
  load_fprints(filename);
  
  if (pcap_compile(pt, &flt, rul?rul:"", 1, 0)) {
    if (rul) {
      pcap_perror(pt,"pcap_compile");
      exit(1);
    }
  }
  
  if (!rul) rul="all";
  fprintf(stderr,"p0f: file: '%s', %d fprints, iface: '%s', rule: '%s'.\n",filename,fips,ifa,rul);
  
  pcap_setfilter(pt, &flt);

  pcap_loop(pt,-1,(pcap_handler)&parse,(void*)0L);
  return 0; //not reached;>
}
