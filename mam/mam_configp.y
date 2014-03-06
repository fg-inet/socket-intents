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
	
	#define MAM_CONFIGP_NOISY_DEBUG 1
	int yydebug=0;
	
	char *p_file = NULL;				/**< policy share library to load */
	struct mam_context *yymctx;			/**< mam context to feed */
	GHashTable *l_set_dict = NULL;		/**< per block set config holder */
	struct evdns_base *l_evdns_base = NULL;	/**< use a special resolvconf for that prefix */
	unsigned int pfx_flags_set = 0;		/**< flags to set */
	unsigned int pfx_flags_values = 0;	/**< values of the flags to set */
	
	char addr_str[INET6_ADDRSTRLEN];	/** string for debug / error printing */
	
	void yyerror(const char *str);
	int yywrap();
		
	int *idup(int i);
%}

%token SEMICOLON OBRACE CBRACE EQUAL SLASH
%token POLICYTOK IFACETOK PREFIXTOK 
%token SETTOK RESOLVCONFTOK ENABLETOK

%union
{
	int number;
	char *string;
	struct sockaddr_in in_sa;
	struct sockaddr_in6 in6_sa;
}

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
	|
	SETTOK name NUMBER
	{g_hash_table_replace(yymctx->policy_set_dict, $2, idup($3));}
	|
	SETTOK name EQUAL NUMBER
	{g_hash_table_replace(yymctx->policy_set_dict, $2, idup($4));}
	;

iface_block:
	IFACETOK name OBRACE iface_statements CBRACE
	{
		printf("WARNING: interfaces configuration not implemented! \n");
	}
	;

iface_statements:
	/* empty */
	;
	
prefix_block:
	PREFIXTOK IN4ADDR SLASH NUMBER OBRACE prefix_statements CBRACE
	{
		// find matching prefixes
		struct sockaddr_in *sa = &($2);
		inet_ntop(AF_INET, &(sa->sin_addr), addr_str, sizeof(addr_str));
		struct src_prefix_model m = {PFX_ANY, NULL, AF_INET, (struct sockaddr *) sa, sizeof(struct sockaddr_in)};
		GSList *listelement = g_slist_find_custom(yymctx->prefixes, (gconstpointer) &m, &compare_src_prefix);
		if (listelement != NULL){
			struct src_prefix_list *spl = listelement->data;
			// set the dns base and set dictionary
			spl->policy_set_dict = l_set_dict;
			spl->evdns_base = l_evdns_base;
			// flag them as configured
			spl->pfx_flags &= (pfx_flags_set ^ spl->pfx_flags);
			spl->pfx_flags |= pfx_flags_values;			
			spl->pfx_flags |= PFX_CONF;
			spl->pfx_flags |= PFX_CONF_PFX;
			// print something
			DLOG(MAM_CONFIGP_NOISY_DEBUG, "prefix %s/%d configured\n", addr_str, $4);
		} else {
			DLOG(MAM_CONFIGP_NOISY_DEBUG, "prefix %s/%d configured but not on any interface\n", addr_str, $4);
			if (l_evdns_base != NULL)
				evdns_base_free(l_evdns_base, 0);
			g_hash_table_destroy(l_set_dict);
		}
		pfx_flags_set = 0;
		pfx_flags_values = 0;
		l_evdns_base = NULL;
		l_set_dict = g_hash_table_new_full(&g_str_hash, &g_str_equal, &free, &free);
	}
	|
	PREFIXTOK IN6ADDR SLASH NUMBER OBRACE prefix_statements CBRACE
	{
		// find matching prefixes
		struct sockaddr_in6 *sa = &($2);
		inet_ntop(AF_INET6, &(sa->sin6_addr), addr_str, sizeof(addr_str));
		struct src_prefix_model m = {PFX_ANY, NULL, AF_INET6, (struct sockaddr *) sa, sizeof(struct sockaddr_in6)};
		GSList *listelement = g_slist_find_custom(yymctx->prefixes, (gconstpointer) &m, &compare_src_prefix);
		if (listelement != NULL){
			struct src_prefix_list *spl = listelement->data;
			// set the dns base and set dictionary
			spl->policy_set_dict = l_set_dict;
			spl->evdns_base = l_evdns_base;
			// flag them as configured
			spl->pfx_flags &= (pfx_flags_set ^ spl->pfx_flags);
			spl->pfx_flags |= pfx_flags_values;			
			spl->pfx_flags |= PFX_CONF;
			spl->pfx_flags |= PFX_CONF_PFX;
			// print something
			DLOG(MAM_CONFIGP_NOISY_DEBUG, "prefix %s/%d configured\n", addr_str, $4);
		} else {
			DLOG(MAM_CONFIGP_NOISY_DEBUG, "prefix %s/%d configured but not on any interface\n", addr_str, $4);
			if(l_evdns_base != NULL)
				evdns_base_free(l_evdns_base, 0);
			g_hash_table_destroy(l_set_dict);
		}
		pfx_flags_set = 0;
		pfx_flags_values = 0;
		l_evdns_base = NULL;
		l_set_dict = g_hash_table_new_full(&g_str_hash, &g_str_equal, &free, &free);
	}
	;


prefix_statements:
	/* empty */
	|
	prefix_statements prefix_statement SEMICOLON
	|
	error SEMICOLON
	;

prefix_statement:
	/* empty */
	|
	SETTOK name name
	{g_hash_table_replace(l_set_dict, $2, $3);}
	|
	SETTOK name EQUAL name
	{g_hash_table_replace(l_set_dict, $2, $4);}
	|
	SETTOK name NUMBER
	{g_hash_table_replace(l_set_dict, $2, idup($3));}
	|
	SETTOK name EQUAL NUMBER
	{g_hash_table_replace(l_set_dict, $2, idup($4));}
	|
	ENABLETOK NUMBER
	{	pfx_flags_set |= PFX_ENABLED; 
		if($2) 
			pfx_flags_values |= PFX_ENABLED; 
		else
			pfx_flags_values &= PFX_ENABLED^PFX_ENABLED; 
	}
	|
	RESOLVCONFTOK QNAME 
	{
		if((l_evdns_base = evdns_base_new(yymctx->ev_base, 0)) != NULL)
			evdns_base_resolv_conf_parse(l_evdns_base, DNS_OPTIONS_ALL, $2);
	}
	;
	
%%

void yyerror(const char *str)
{
        DLOG(0 ,"error: %s\n",str);
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

int *idup (int i)
{
	int *p = malloc(sizeof(int));
	if (p != NULL)
		*p = i;
	return p;
}
