/** \file mam_configs.l
 *
 *  \copyright Copyright 2013-2015 Philipp Schmidt, Theresa Enghardt, and Mirko Palmer.
 *  All rights reserved. This project is released under the New BSD License.
 */

%{
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "mam_configp.h"
#include "clib/dlog.h"

%}

%option noinput
%option nounput

IPV4ADDRESS      (([[:digit:]]{1,3}"."){3}([[:digit:]]{1,3}))
hex4             ([[:xdigit:]]{1,4})
hexseq           ({hex4}(:{hex4})*)
hexpart          (({hexseq}::({hexseq}?))|(::{hexseq})|({hexseq}:{hexseq}))
IPV6ADDRESS      ({hexpart}(":"{IPV4ADDRESS})?)

%%
#.*\n					/* ignore comments */;

\"(\\\"|[^"])*\"		yylval.string=strndup(yytext+1, strlen(yytext)-2); return QNAME;

policy					return POLICYTOK;
prefix                  return PREFIXTOK;
iface                   return IFACETOK;
set                		return SETTOK;
enabled					return ENABLETOK;

resolvconf              return RESOLVCONFTOK;
nameserver              return NAMESERVERTOK;

\{                      return OBRACE;
\}                      return CBRACE;
=                      	return EQUAL;
\/                     	return SLASH;
;                       return SEMICOLON;



{IPV4ADDRESS}			{ if(inet_pton(AF_INET,  yytext, &(yylval.in_sa.sin_addr)) == 1 ) 
								{		
									#ifdef HAVE_SOCKADDR_LEN
										yylval.in_sa.sin_len = sizeof(struct sockaddr_in);
									#endif
									yylval.in_sa.sin_family = AF_INET;
									yylval.in_sa.sin_port = 0;
									return IN4ADDR; 
								} else {
									DLOG(1, "ERROR: %s is not a valid IPv4 address\n", yytext);
								} };
								
{IPV6ADDRESS}			{ if(inet_pton(AF_INET6, yytext, &(yylval.in6_sa.sin6_addr)) == 1 )
								{
									#ifdef HAVE_SOCKADDR_LEN
										yylval.in6_sa.sin6_len = sizeof(struct sockaddr_in);
									#endif
									yylval.in6_sa.sin6_family = AF_INET6;
									yylval.in6_sa.sin6_port = 0;
									return IN6ADDR; 
								} else {
									DLOG(1, "ERROR: %s is not a valid IPv6 address\n", yytext);
								} };

[0-9][0-9]*				{yylval.ival=atoi(yytext); return INTNUMBER;}
(([0-9]+(\.[0-9]*)?)|([0-9]*\.[0-9]+)) {yylval.dval = atof(yytext); return DOUBLENUMBER;}
[a-zA-Z_][a-zA-Z0-9_]*    yylval.string=strdup(yytext); return LNAME;

\n                      /* ignore EOL */;
[ \t]+                  /* ignore whitespace */;
%%
