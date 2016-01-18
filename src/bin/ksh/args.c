/*
 * Copyright (c) 2016 Henning Matyschok
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED
 * WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT,
 * INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES
 * (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN
 * ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE
 * POSSIBILITY OF SUCH DAMAGE.
 */

#include "sh.h"

/*
 * XXX: This file should understand as workaround regarding
 * XXX: partially refactoring activities targeting current 
 * XXX: implementation of ksh(1).
 * XXX:
 * XXX: Intentionally, I'll add more by strdup(3) performed 
 * XXX: copies of constant declared and initialized string
 * XXX" literals.
 */
 
#include <err.h>
#include <stdlib.h>
#include <sysexits.h>

char *ksh_cmd;

/*
 * Various builtin commands and options.
 */
  
char *read_cmd;
char *read_options;
char *read_reply;

char *set_cmd;  
char *set_options; 

char *unalias_cmd;  
char *unalias_options;


/*
 * By p_time accepted literals.
 */

char *p_time_ws;
char *p_time_nl;
char *p_time_real;
char *p_time_user;
char *p_time_sys;
char *p_time_system_nl;

/*
 * Holds copy of string denotes version.
 */

char *_ksh_version;

/*
 * Holds copy of string denotes shell name.
 */

char *_ksh_name;

/*
 * Release by initargs bound ressources.
 */
static void 	
args_atexit(void)
{
	free(ksh_cmd);

	free(read_cmd);
	free(read_options);
	free(read_reply);
	
	free(set_cmd);  
	free(set_options); 
	
	free(unalias_cmd);
	free(unalias_options);
	
	free(p_time_ws);
	free(p_time_nl);
	free(p_time_real);
	free(p_time_user);
	free(p_time_sys);
	free(p_time_system_nl);
	
	free(_ksh_version);
	free(_ksh_name);
}

void 
initargs(void)
{
	ksh_cmd = strdup("ksh");
	
	read_cmd = strdup("read");
	read_options = strdup("-r");
	read_reply = strdup("REPLY");
	
	set_cmd = strdup("set");  
	set_options = strdup("-"); 
	
	unalias_cmd = strdup("unalias");  
	unalias_options = strdup("-ta");
	
	
	p_time_ws = strdup(" ");
	p_time_ws = strdup("\n");
	p_time_real = strdup(" real ");
	p_time_user = strdup(" user ");
	p_time_sys = strdup("sys  ");
	p_time_system_nl = strdup(" system\n");
	
	_ksh_version = strdup(ksh_version);
	_ksh_name = strdup(kshname);
	
	if (atexit(args_atexit) < 0)
		err(EX_OSERR, "%s", strerror(errno));
}







