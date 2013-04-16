%{
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "mam_configp.h"
%}

%%
#.*\n					/* ignore comments */;

\"(\\\"|[^"])*\"		yylval.string=strndup(yytext+1, strlen(yytext)-2); return QNAME;

policy					return POLICYTOK;
prefix                  return PREFIXTOK;
iface                   return IFACETOK;
set                		return SETTOK;

nameserver              return NAMESERVERTOK;
search                	return SEARCHTOK;

\{                      return OBRACE;
\}                      return CBRACE;
=                      	return EQUAL;
\/                     	return SLASH;
;                       return SEMICOLON;

[0-9]+.[0-9]+.[0-9]+.[0-9]+		if(inet_pton(AF_INET,  yytext, &(yylval.in_sa)) == 1 ) return IN4ADDR; else yyerror("%s is no valid ip address");
[0-9a-fA-F:]:[0-9a-fA-F:]+		if(inet_pton(AF_INET6, yytext, &(yylval.in_sa)) == 1 ) return IN6ADDR; else yyerror("%s is no valid ipv6 address");

[a-zA-Z][a-zA-Z0-9]*    yylval.string=strdup(yytext); return LNAME;
\n                      /* ignore EOL */;
[ \t]+                  /* ignore whitespace */;
%%
