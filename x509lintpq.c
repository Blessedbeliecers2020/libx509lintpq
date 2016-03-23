/* libx509lintpq - run x509lint from a PostgreSQL function
 * Written by Rob Stradling
 * Copyright (C) 2016 COMODO CA Limited
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */

#include "postgres.h"
#include "funcapi.h"
#include "fmgr.h"

#include "x509lint/messages.h"
#include "x509lint/checks.h"

#include <gnutls/x509.h>
#include <stdlib.h>
#include <string.h>


#ifdef PG_MODULE_MAGIC
PG_MODULE_MAGIC;
#endif


/******************************************************************************
 * _PG_init()                                                                 *
 ******************************************************************************/
void _PG_init(void)
{
	check_init();
}


/******************************************************************************
 * _PG_fini()                                                                 *
 ******************************************************************************/
void _PG_fini(void)
{
	check_finish();
}


typedef struct tX509lintCtx_st{
	char* m_messages;
	char* m_nextMessage;
} tX509lintCtx;


/******************************************************************************
 * x509lint_embedded()                                                        *
 ******************************************************************************/
PG_FUNCTION_INFO_V1(x509lint_embedded);
Datum x509lint_embedded(
	PG_FUNCTION_ARGS
)
{
	tX509lintCtx* t_x509lintCtx;
	FuncCallContext* t_funcCtx;

	if (SRF_IS_FIRSTCALL()) {
		MemoryContext t_oldMemoryCtx;

		/* Create a function context for cross-call persistence */
		t_funcCtx = SRF_FIRSTCALL_INIT();
		/* Switch to memory context appropriate for multiple function
		  calls */
		t_oldMemoryCtx = MemoryContextSwitchTo(
			t_funcCtx->multi_call_memory_ctx
		);

		/* Allocate memory for our user-defined structure and initialize
		  it */
		t_funcCtx->user_fctx = t_x509lintCtx
						= palloc(sizeof(tX509lintCtx));
		memset(t_x509lintCtx, '\0', sizeof(tX509lintCtx));

		/* One-time setup code */
		if (!PG_ARGISNULL(0)) {
			bytea* t_bytea = PG_GETARG_BYTEA_P(0);
			CertType t_certType = SubscriberCertificate;
			if (!PG_ARGISNULL(1))
				t_certType = PG_GETARG_INT32(1);
			check((unsigned char*)VARDATA(t_bytea),
				VARSIZE(t_bytea) - VARHDRSZ, DER, t_certType);
			t_x509lintCtx->m_nextMessage = t_x509lintCtx->m_messages
							= get_messages();
			if (t_x509lintCtx->m_messages)
				t_funcCtx->max_calls = 512;
		}
		MemoryContextSwitchTo(t_oldMemoryCtx);
	}

	/* Each-time setup code */
	t_funcCtx = SRF_PERCALL_SETUP();
	t_x509lintCtx = t_funcCtx->user_fctx;

	if ((t_funcCtx->call_cntr < t_funcCtx->max_calls)
					&& (*(t_x509lintCtx->m_nextMessage))) {
		char* t_message = t_x509lintCtx->m_nextMessage;
		char* t_next = strchr(t_message, '\n');
		text* t_text = palloc(t_next - t_message + VARHDRSZ);
		SET_VARSIZE(t_text, t_next - t_message + VARHDRSZ);
		memcpy((void*)VARDATA(t_text), t_message, t_next - t_message);
		t_x509lintCtx->m_nextMessage = t_next + 1;
		SRF_RETURN_NEXT(t_funcCtx, PointerGetDatum(t_text));
	}
	else {
		if (t_x509lintCtx->m_messages)
			free(t_x509lintCtx->m_messages);
		SRF_RETURN_DONE(t_funcCtx);
	}
}
