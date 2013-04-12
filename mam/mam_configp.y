/** a parser for mammas config file 
 */

%{
    #include <unistd.h>
    #include <stdio.h>	
	#include <glib.h>
	
	extern int yylex (void);
	extern void yyset_debug(int);
	
	extern FILE* yyin;
	
	char *policy_file;				/**< policy share library to load */
	GHashTable *global_set_dict;	/**< global set config holder */
	
	GHashTable *local_set_dict;		/**< per block set config holder */
	
	void yyerror(const char *str)
	{
	        fprintf(stderr,"error: %s\n",str);
	}

	int yywrap()
	{
	        return 1;
	}
		
%}

%token SEMICOLON OBRACE CBRACE
%token POLICYTOK OPTSTOC IFACETOK PREFIXTOK 
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
	/* empty */ | config_blocks config_block SEMICOLON
	;

config_block:
	options_block | iface_block	| prefix_block | policy_stmt 
	;

name:
	LNAME | QNAME
	;
	
policy_stmt:
	POLICYTOK name SEMICOLON
	{ policy_file = $2; }
	;

options_block:
	OPTSTOC OBRACE options_statements CBRACE SEMICOLON
    ;

options_statements:
	/* empty */ | options_statements option_set SEMICOLON
	;

option_set:
	SETTOK name name
	{g_hash_table_replace(global_set_dict, $2, $3);}
	;

iface_block:
	IFACETOK name OBRACE iface_statements CBRACE SEMICOLON

iface_statements:
	/* empty */
	;
	
prefix_block:
	PREFIXTOK name OBRACE prefix_statements CBRACE SEMICOLON

prefix_statements:
	/* empty */
	;
	
%%

void mam_read_config(int config_fd, GHashTable **set_dict )
{

	/* open file */
	yyin = fdopen(config_fd, "r");
	fseek(yyin, 0, SEEK_SET);

	/* prepair globals used during parsing */
	if(*set_dict == NULL)
		*set_dict = g_hash_table_new_full(&g_str_hash, &g_str_equal, &free, &free);
	global_set_dict = *set_dict;
	local_set_dict = g_hash_table_new_full(&g_str_hash, &g_str_equal, &free, &free);

	/* do parse */
    yyset_debug(1);
    yyparse();

	/* clean up */
	fclose(yyin);
	g_hash_table_destroy(local_set_dict);

}

