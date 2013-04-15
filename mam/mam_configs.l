%{
#include <stdio.h>
#include <string.h>
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
;                       return SEMICOLON;

[a-zA-Z][a-zA-Z0-9]*    yylval.string=strdup(yytext); return LNAME;
\n                      /* ignore EOL */;
[ \t]+                  /* ignore whitespace */;
%%
