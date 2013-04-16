/** a parser for mammas config file 
 */

%{
    #include <unistd.h>
    #include <stdio.h>
	#include <netinet/in.h>
    #include <arpa/inet.h>
	
	#include "mam.h"
	
	extern int yylex (void);
	extern void yyset_debug(int);
	
	extern FILE* yyin;
	// int yydebug=1;
	
	char *p_file = NULL;				/**< policy share library to load */
	struct mam_context *yymctx;			/**< mam context to feed */
	GHashTable *l_set_dict = NULL;		/**< per block set config holder */
	
	void yyerror(const char *str);
	int yywrap();
		
%}

%token SEMICOLON OBRACE CBRACE EQUAL SLASH
%token POLICYTOK IFACETOK PREFIXTOK 
%token SETTOK NAMESERVERTOK SEARCHTOK

%union
{
	int number;
	char *string;
	struct sockaddr_in in_sa;
	struct sockaddr_in6 in6_sa;
}

%token <number> BOOL
%token <number> NUMBER
%token <string> LNAME QNAME
%token <in_sa>  IN4ADDR
%token <in6_sa> IN6ADDR
%type <string> name


%start config_blocks
%%

config_blocks:
	/* empty */ | config_blocks config_block SEMICOLON | error SEMICOLON
	;

config_block:
	iface_block	| prefix_block | policy_block
	;

name:
	LNAME | QNAME
	;
	
policy_block:
	POLICYTOK QNAME OBRACE policy_statements CBRACE
	{ p_file = $2; }
	|
	POLICYTOK QNAME
	{ p_file = $2; }
	;

policy_statements:
	/* empty */ 
	|
	policy_statements policy_set SEMICOLON
	|
	error SEMICOLON
	;

policy_set:
	SETTOK name name
	{g_hash_table_replace(yymctx->policy_set_dict, $2, $3);}
	|
	SETTOK name EQUAL name
	{g_hash_table_replace(yymctx->policy_set_dict, $2, $4);}
	;

iface_block:
	IFACETOK name OBRACE iface_statements CBRACE

iface_statements:
	/* empty */
	;
	
prefix_block:
	PREFIXTOK IN4ADDR SLASH NUMBER OBRACE prefix_statements CBRACE SEMICOLON
	{
 		for( struct src_prefix_list *spl = lookup_source_prefix( yymctx->prefixes, NULL, AF_INET, (struct sockaddr *) &($2) ) ;
		spl != NULL ;  spl = lookup_source_prefix( spl, NULL, AF_INET, (struct sockaddr *) &($2) ) )
		{
			spl->policy_set_dict = l_set_dict;
		}
		l_set_dict = g_hash_table_new_full(&g_str_hash, &g_str_equal, &free, &free);
	}
	;

prefix_statements:
	/* empty */
	|
	SETTOK name name
	{g_hash_table_replace(l_set_dict, $2, $3);}
	|
	SETTOK name EQUAL name
	{g_hash_table_replace(l_set_dict, $2, $4);}
	|
	NAMESERVERTOK
	|
	SEARCHTOK
	;
	
%%

void yyerror(const char *str)
{
        fprintf(stderr,"error: %s\n",str);
}

int yywrap()
{
        return 1;
}

void mam_read_config(int config_fd, char **p_file_out, struct mam_context *ctx)
{

	/* open file */
	int config_fd2 = dup(config_fd);
	yyin = fdopen(config_fd2, "r");
	fseek(yyin, 0, SEEK_SET);

	/* prepair globals used during parsing */
	yymctx = ctx;
	if(yymctx->policy_set_dict != NULL)
		g_hash_table_destroy(yymctx->policy_set_dict);
	yymctx->policy_set_dict = g_hash_table_new_full(&g_str_hash, &g_str_equal, &free, &free);
	l_set_dict = g_hash_table_new_full(&g_str_hash, &g_str_equal, &free, &free);

	/* do parse */
    yyparse();
	
	if(p_file != NULL)
		*p_file_out = p_file;

	/* clean up */
	fclose(yyin);
	g_hash_table_destroy(l_set_dict);

}

