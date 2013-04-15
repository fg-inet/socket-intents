/** a parser for mammas config file 
 */

%{
    #include <unistd.h>
    #include <stdio.h>	
	#include "mam.h"
	
	extern int yylex (void);
	extern void yyset_debug(int);
	
	extern FILE* yyin;
	// int yydebug=1;
	
	char *p_file = NULL;				/**< policy share library to load */
	GHashTable *p_set_dict = NULL;		/**< global set config holder */
	GHashTable *l_set_dict = NULL;		/**< per block set config holder */
	
	void yyerror(const char *str);
	int yywrap();
		
%}

%token SEMICOLON OBRACE CBRACE EQUAL
%token POLICYTOK IFACETOK PREFIXTOK 
%token SETTOK NAMESERVERTOK SEARCHTOK

%union
{
	int number;
	char *string;
}

%token <number> BOOL
%token <number> NUMBER
%token <string> LNAME QNAME
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
	{g_hash_table_replace(p_set_dict, $2, $3);}
	|
	SETTOK name EQUAL name
	{g_hash_table_replace(p_set_dict, $2, $4);}
	;

iface_block:
	IFACETOK name OBRACE iface_statements CBRACE

iface_statements:
	/* empty */
	;
	
prefix_block:
	PREFIXTOK name OBRACE prefix_statements CBRACE SEMICOLON

prefix_statements:
	/* empty */
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

void mam_read_config(int config_fd, char **p_file_out, GHashTable **p_dict_out)
{

	/* open file */
	int config_fd2 = dup(config_fd);
	yyin = fdopen(config_fd2, "r");
	fseek(yyin, 0, SEEK_SET);

	/* prepair globals used during parsing */
	if(*p_dict_out == NULL)
		*p_dict_out = g_hash_table_new_full(&g_str_hash, &g_str_equal, &free, &free);
	p_set_dict = *p_dict_out;
	l_set_dict = g_hash_table_new_full(&g_str_hash, &g_str_equal, &free, &free);

	/* do parse */
    yyparse();
	
	if(p_file != NULL)
		*p_file_out = p_file;

	/* clean up */
	fclose(yyin);
	g_hash_table_destroy(l_set_dict);

}

