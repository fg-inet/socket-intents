%{
#include <stdio.h>
#include <string.h>
#include "mam_configp.h"
%}

%%
#.*\n			/* ignore comments */;

policy					return POLICYTOK;
options                 return OPTSTOC;
prefix                  return PREFIXTOK;
iface                   return IFACETOK;

nameserver              return NAMESERVERTOK;
search                	return SEARCHTOK;

\"(\\\"|[^"])*\"		yylval.string=strndup(yytext+1, strlen(yytext)-2); return QNAME;
[a-zA-Z][a-zA-Z0-9]*    yylval.string=strdup(yytext); return LNAME;
\{                      return OBRACE;
\}                      return CBRACE;
;                       return SEMICOLON;
\n                      /* ignore EOL */;
[ \t]+                  /* ignore whitespace */;
%%
