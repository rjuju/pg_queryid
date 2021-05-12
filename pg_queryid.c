/*-------------------------------------------------------------------------
 *
 * pg_queryid.c: External query fingerprinting for PostgreSQL.
 *
 * This extension imports PostgreSQL's fingerprinting functions and adds some
 * additional configuration options for its heuristic.
 *
 * This program is open source, licensed under the PostgreSQL license.
 * For license terms, see the LICENSE file.
 *
 * Copyright (c) 2008-2021, PostgreSQL Global Development Group
 * Copyright (C) 2021: Julien Rouhaud
 *
 *-------------------------------------------------------------------------
 */

#include "postgres.h"

#if PG_VERSION_NUM < 140000
#error "Requires PostgreSQL 14 or above"
#endif

#include "catalog/pg_collation.h"
#include "catalog/pg_type.h"
#include "common/hashfn.h"
#include "miscadmin.h"
#include "parser/analyze.h"
#include "tcop/tcopprot.h"
#include "utils/builtins.h"
#include "utils/guc.h"
#include "utils/lsyscache.h"
#include "utils/queryjumble.h"
#include "utils/syscache.h"
#include "utils/varlena.h"

PG_MODULE_MAGIC;

/*
 * Wrappers around pgq_AppendJumble to encapsulate details of serialization
 * of individual local variable elements.
 */
#define PGQ_APP_JUMB(item) \
	pgq_AppendJumble(jstate, (const unsigned char *) &(item), sizeof(item))
#define PGQ_APP_JUMB_STRING(str) \
	pgq_AppendJumble(jstate, (const unsigned char *) (str), strlen(str) + 1)

typedef enum pgqKind
{
	pgq_Rel,
	pgq_Func,
	pgq_Seq,
	pgq_Coll,
	pgq_Typ
} pgqKind;

/* Saved hook values in case of unload */
static post_parse_analyze_hook_type prev_post_parse_analyze_hook = NULL;

/*---- Local variables ----*/

static bool is_spl = false;

/*---- GUC variables ----*/

static bool pgq_use_names;
static bool pgq_ignore_schema;
static bool pgq_ignore_temp;

/*---- Function declarations ----*/

void		_PG_init(void);
void		_PG_fini(void);

PG_FUNCTION_INFO_V1(pg_queryid);

static void pgq_post_parse_analyze(ParseState *pstate, Query *query,
									JumbleState *jstate);

static void pgq_AppendJumble(JumbleState *jstate,
							 const unsigned char *item, Size size);
static uint64 pgq_compute_utility_queryid(const char *str, int query_location, int query_len);
static void pgq_JumbleExpr(JumbleState *jstate, Node *node);
static JumbleState *pgq_JumbleQuery(Query *query, const char *querytext);
static void pgq_JumbleOid(JumbleState *jstate, pgqKind kind, Oid oid);
static bool pgq_JumbleQueryInternal(JumbleState *jstate, Query *query);
static bool pgq_JumbleRangeTable(JumbleState *jstate, List *rtable);
static void pgq_JumbleRowMarks(JumbleState *jstate, List *rowMarks);
static void pgq_RecordConstLocation(JumbleState *jstate, int location);

/*
 * Module load callback
 */
void
_PG_init(void)
{
	char	   *spl_string;
	List	   *spl;

	/*
	 * We don't want to change the queryid fingerprinting algorithm dynamically
	 * as it would lead to duplicated entries for extensions like
	 * pg_stat_statements which rely on the queryid.  We however still allow to
	 * dynamically load the module as pg_queryid() SRF can be used to compute
	 * the queryid of a given query with core implementation.
	 */
	if (!process_shared_preload_libraries_in_progress)
	{
		is_spl = false;
		return;
	}

	is_spl = true;
	spl_string = pstrdup(shared_preload_libraries_string);
	if (!SplitIdentifierString(spl_string, ',', &spl))
		elog(ERROR, "Could not parse shared_preload_libraries");

	if (strcmp(llast(spl), "pg_queryid") != 0)
		elog(ERROR, "pg_queryid should be last the last element in shared_preload_libraries");

	list_free(spl);
	pfree(spl_string);

	/*
	 * Define (or redefine) custom GUC variables.
	 */
	DefineCustomBoolVariable("pg_queryid.use_object_names",
							"Fingerprint queries using object names rather than Oids.",
							NULL,
							&pgq_use_names,
							true,
							PGC_SUSET,
							0,
							NULL,
							NULL,
							NULL);

	DefineCustomBoolVariable("pg_queryid.ignore_schema",
							"Ignore schema for query fingerprinting.",
							NULL,
							&pgq_ignore_schema,
							false,
							PGC_SUSET,
							0,
							NULL,
							NULL,
							NULL);

	DefineCustomBoolVariable("pg_queryid.ignore_temp_tables",
							"Don't fingerprint queries using temporary relations.",
							NULL,
							&pgq_ignore_temp,
							false,
							PGC_SUSET,
							0,
							NULL,
							NULL,
							NULL);

	EmitWarningsOnPlaceholders("pg_queryid");

	/*
	 * Install hooks.
	 */
	prev_post_parse_analyze_hook = post_parse_analyze_hook;
	post_parse_analyze_hook = pgq_post_parse_analyze;
}

/*
 * Module unload callback
 */
void
_PG_fini(void)
{
	/* Uninstall hooks. */
	post_parse_analyze_hook = prev_post_parse_analyze_hook;
}


static void
pgq_post_parse_analyze(ParseState *pstate, Query *query, JumbleState *jstate)
{
	JumbleState *pgq_jstate;

	if (query->queryId != UINT64CONST(0) || jstate != NULL)
		elog(ERROR, "pg_queryid: a queryid has already been calculated");

	pgq_jstate = pgq_JumbleQuery(query, pstate->p_sourcetext);

	if (prev_post_parse_analyze_hook)
		prev_post_parse_analyze_hook(pstate, query, pgq_jstate);
}

/*
 * AppendJumble: Append a value that is substantive in a given query to
 * the current jumble.
 */
static void
pgq_AppendJumble(JumbleState *jstate, const unsigned char *item, Size size)
{
	unsigned char *jumble = jstate->jumble;
	Size		jumble_len = jstate->jumble_len;

	/*
	 * Whenever the jumble buffer is full, we hash the current contents and
	 * reset the buffer to contain just that hash value, thus relying on the
	 * hash to summarize everything so far.
	 */
	while (size > 0)
	{
		Size		part_size;

		if (jumble_len >= JUMBLE_SIZE)
		{
			uint64		start_hash;

			start_hash = DatumGetUInt64(hash_any_extended(jumble,
														  JUMBLE_SIZE, 0));
			memcpy(jumble, &start_hash, sizeof(start_hash));
			jumble_len = sizeof(start_hash);
		}
		part_size = Min(size, JUMBLE_SIZE - jumble_len);
		memcpy(jumble + jumble_len, item, part_size);
		jumble_len += part_size;
		item += part_size;
		size -= part_size;
	}
	jstate->jumble_len = jumble_len;
}

/*
 * Compute a query identifier for the given utility query string.
 */
static uint64
pgq_compute_utility_queryid(const char *query_text, int query_location,
							int query_len)
{
	uint64 queryId;
	const char *sql;

	/*
	 * Confine our attention to the relevant part of the string, if the
	 * query is a portion of a multi-statement source string.
	 */
	sql = CleanQuerytext(query_text, &query_location, &query_len);

	queryId = DatumGetUInt64(hash_any_extended((const unsigned char *) sql,
											   query_len, 0));

	/*
	 * If we are unlucky enough to get a hash of zero(invalid), use
	 * queryID as 2 instead, queryID 1 is already in use for normal
	 * statements.
	 */
	if (queryId == UINT64CONST(0))
		queryId = UINT64CONST(2);

	return queryId;
}

/*
 * Jumble an expression tree
 *
 * In general this function should handle all the same node types that
 * expression_tree_walker() does, and therefore it's coded to be as parallel
 * to that function as possible.  However, since we are only invoked on
 * queries immediately post-parse-analysis, we need not handle node types
 * that only appear in planning.
 *
 * Note: the reason we don't simply use expression_tree_walker() is that the
 * point of that function is to support tree walkers that don't care about
 * most tree node types, but here we care about all types.  We should complain
 * about any unrecognized node type.
 */
static void
pgq_JumbleExpr(JumbleState *jstate, Node *node)
{
	ListCell   *temp;

	if (node == NULL)
		return;

	/* Guard against stack overflow due to overly complex expressions */
	check_stack_depth();

	/*
	 * We always emit the node's NodeTag, then any additional fields that are
	 * considered significant, and then we recurse to any child nodes.
	 */
	PGQ_APP_JUMB(node->type);

	switch (nodeTag(node))
	{
		case T_Var:
			{
				Var		   *var = (Var *) node;

				if(pgq_use_names && !IS_SPECIAL_VARNO(var->varno))
				{

				}
				else
				{
					PGQ_APP_JUMB(var->varno);
					PGQ_APP_JUMB(var->varattno);
					PGQ_APP_JUMB(var->varlevelsup);
				}
			}
			break;
		case T_Const:
			{
				Const	   *c = (Const *) node;

				/* We jumble only the constant's type, not its value */
				PGQ_APP_JUMB(c->consttype);
				/* Also, record its parse location for query normalization */
				pgq_RecordConstLocation(jstate, c->location);
			}
			break;
		case T_Param:
			{
				Param	   *p = (Param *) node;

				PGQ_APP_JUMB(p->paramkind);
				PGQ_APP_JUMB(p->paramid);
				PGQ_APP_JUMB(p->paramtype);
				/* Also, track the highest external Param id */
				if (p->paramkind == PARAM_EXTERN &&
					p->paramid > jstate->highest_extern_param_id)
					jstate->highest_extern_param_id = p->paramid;
			}
			break;
		case T_Aggref:
			{
				Aggref	   *expr = (Aggref *) node;

				pgq_JumbleOid(jstate, pgq_Func, expr->aggfnoid);
				pgq_JumbleExpr(jstate, (Node *) expr->aggdirectargs);
				pgq_JumbleExpr(jstate, (Node *) expr->args);
				pgq_JumbleExpr(jstate, (Node *) expr->aggorder);
				pgq_JumbleExpr(jstate, (Node *) expr->aggdistinct);
				pgq_JumbleExpr(jstate, (Node *) expr->aggfilter);
			}
			break;
		case T_GroupingFunc:
			{
				GroupingFunc *grpnode = (GroupingFunc *) node;

				pgq_JumbleExpr(jstate, (Node *) grpnode->refs);
			}
			break;
		case T_WindowFunc:
			{
				WindowFunc *expr = (WindowFunc *) node;

				PGQ_APP_JUMB(expr->winfnoid);
				PGQ_APP_JUMB(expr->winref);
				pgq_JumbleExpr(jstate, (Node *) expr->args);
				pgq_JumbleExpr(jstate, (Node *) expr->aggfilter);
			}
			break;
		case T_SubscriptingRef:
			{
				SubscriptingRef *sbsref = (SubscriptingRef *) node;

				pgq_JumbleExpr(jstate, (Node *) sbsref->refupperindexpr);
				pgq_JumbleExpr(jstate, (Node *) sbsref->reflowerindexpr);
				pgq_JumbleExpr(jstate, (Node *) sbsref->refexpr);
				pgq_JumbleExpr(jstate, (Node *) sbsref->refassgnexpr);
			}
			break;
		case T_FuncExpr:
			{
				FuncExpr   *expr = (FuncExpr *) node;

				pgq_JumbleOid(jstate, pgq_Func, expr->funcid);
				pgq_JumbleExpr(jstate, (Node *) expr->args);
			}
			break;
		case T_NamedArgExpr:
			{
				NamedArgExpr *nae = (NamedArgExpr *) node;

				PGQ_APP_JUMB(nae->argnumber);
				pgq_JumbleExpr(jstate, (Node *) nae->arg);
			}
			break;
		case T_OpExpr:
		case T_DistinctExpr:	/* struct-equivalent to OpExpr */
		case T_NullIfExpr:		/* struct-equivalent to OpExpr */
			{
				OpExpr	   *expr = (OpExpr *) node;

				PGQ_APP_JUMB(expr->opno);
				pgq_JumbleExpr(jstate, (Node *) expr->args);
			}
			break;
		case T_ScalarArrayOpExpr:
			{
				ScalarArrayOpExpr *expr = (ScalarArrayOpExpr *) node;

				PGQ_APP_JUMB(expr->opno);
				PGQ_APP_JUMB(expr->useOr);
				pgq_JumbleExpr(jstate, (Node *) expr->args);
			}
			break;
		case T_BoolExpr:
			{
				BoolExpr   *expr = (BoolExpr *) node;

				PGQ_APP_JUMB(expr->boolop);
				pgq_JumbleExpr(jstate, (Node *) expr->args);
			}
			break;
		case T_SubLink:
			{
				SubLink    *sublink = (SubLink *) node;

				PGQ_APP_JUMB(sublink->subLinkType);
				PGQ_APP_JUMB(sublink->subLinkId);
				pgq_JumbleExpr(jstate, (Node *) sublink->testexpr);
				pgq_JumbleQueryInternal(jstate, castNode(Query, sublink->subselect));
			}
			break;
		case T_FieldSelect:
			{
				FieldSelect *fs = (FieldSelect *) node;

				PGQ_APP_JUMB(fs->fieldnum);
				pgq_JumbleExpr(jstate, (Node *) fs->arg);
			}
			break;
		case T_FieldStore:
			{
				FieldStore *fstore = (FieldStore *) node;

				pgq_JumbleExpr(jstate, (Node *) fstore->arg);
				pgq_JumbleExpr(jstate, (Node *) fstore->newvals);
			}
			break;
		case T_RelabelType:
			{
				RelabelType *rt = (RelabelType *) node;

				PGQ_APP_JUMB(rt->resulttype);
				pgq_JumbleExpr(jstate, (Node *) rt->arg);
			}
			break;
		case T_CoerceViaIO:
			{
				CoerceViaIO *cio = (CoerceViaIO *) node;

				PGQ_APP_JUMB(cio->resulttype);
				pgq_JumbleExpr(jstate, (Node *) cio->arg);
			}
			break;
		case T_ArrayCoerceExpr:
			{
				ArrayCoerceExpr *acexpr = (ArrayCoerceExpr *) node;

				PGQ_APP_JUMB(acexpr->resulttype);
				pgq_JumbleExpr(jstate, (Node *) acexpr->arg);
				pgq_JumbleExpr(jstate, (Node *) acexpr->elemexpr);
			}
			break;
		case T_ConvertRowtypeExpr:
			{
				ConvertRowtypeExpr *crexpr = (ConvertRowtypeExpr *) node;

				PGQ_APP_JUMB(crexpr->resulttype);
				pgq_JumbleExpr(jstate, (Node *) crexpr->arg);
			}
			break;
		case T_CollateExpr:
			{
				CollateExpr *ce = (CollateExpr *) node;

				pgq_JumbleOid(jstate, pgq_Coll, ce->collOid);
				pgq_JumbleExpr(jstate, (Node *) ce->arg);
			}
			break;
		case T_CaseExpr:
			{
				CaseExpr   *caseexpr = (CaseExpr *) node;

				pgq_JumbleExpr(jstate, (Node *) caseexpr->arg);
				foreach(temp, caseexpr->args)
				{
					CaseWhen   *when = lfirst_node(CaseWhen, temp);

					pgq_JumbleExpr(jstate, (Node *) when->expr);
					pgq_JumbleExpr(jstate, (Node *) when->result);
				}
				pgq_JumbleExpr(jstate, (Node *) caseexpr->defresult);
			}
			break;
		case T_CaseTestExpr:
			{
				CaseTestExpr *ct = (CaseTestExpr *) node;

				pgq_JumbleOid(jstate, pgq_Typ, ct->typeId);
			}
			break;
		case T_ArrayExpr:
			pgq_JumbleExpr(jstate, (Node *) ((ArrayExpr *) node)->elements);
			break;
		case T_RowExpr:
			pgq_JumbleExpr(jstate, (Node *) ((RowExpr *) node)->args);
			break;
		case T_RowCompareExpr:
			{
				RowCompareExpr *rcexpr = (RowCompareExpr *) node;

				PGQ_APP_JUMB(rcexpr->rctype);
				pgq_JumbleExpr(jstate, (Node *) rcexpr->largs);
				pgq_JumbleExpr(jstate, (Node *) rcexpr->rargs);
			}
			break;
		case T_CoalesceExpr:
			pgq_JumbleExpr(jstate, (Node *) ((CoalesceExpr *) node)->args);
			break;
		case T_MinMaxExpr:
			{
				MinMaxExpr *mmexpr = (MinMaxExpr *) node;

				PGQ_APP_JUMB(mmexpr->op);
				pgq_JumbleExpr(jstate, (Node *) mmexpr->args);
			}
			break;
		case T_SQLValueFunction:
			{
				SQLValueFunction *svf = (SQLValueFunction *) node;

				PGQ_APP_JUMB(svf->op);
				/* type is fully determined by op */
				PGQ_APP_JUMB(svf->typmod);
			}
			break;
		case T_XmlExpr:
			{
				XmlExpr    *xexpr = (XmlExpr *) node;

				PGQ_APP_JUMB(xexpr->op);
				pgq_JumbleExpr(jstate, (Node *) xexpr->named_args);
				pgq_JumbleExpr(jstate, (Node *) xexpr->args);
			}
			break;
		case T_NullTest:
			{
				NullTest   *nt = (NullTest *) node;

				PGQ_APP_JUMB(nt->nulltesttype);
				pgq_JumbleExpr(jstate, (Node *) nt->arg);
			}
			break;
		case T_BooleanTest:
			{
				BooleanTest *bt = (BooleanTest *) node;

				PGQ_APP_JUMB(bt->booltesttype);
				pgq_JumbleExpr(jstate, (Node *) bt->arg);
			}
			break;
		case T_CoerceToDomain:
			{
				CoerceToDomain *cd = (CoerceToDomain *) node;

				PGQ_APP_JUMB(cd->resulttype);
				pgq_JumbleExpr(jstate, (Node *) cd->arg);
			}
			break;
		case T_CoerceToDomainValue:
			{
				CoerceToDomainValue *cdv = (CoerceToDomainValue *) node;

				pgq_JumbleOid(jstate, pgq_Typ, cdv->typeId);
			}
			break;
		case T_SetToDefault:
			{
				SetToDefault *sd = (SetToDefault *) node;

				pgq_JumbleOid(jstate, pgq_Typ, sd->typeId);
			}
			break;
		case T_CurrentOfExpr:
			{
				CurrentOfExpr *ce = (CurrentOfExpr *) node;

				PGQ_APP_JUMB(ce->cvarno);
				if (ce->cursor_name)
					PGQ_APP_JUMB_STRING(ce->cursor_name);
				PGQ_APP_JUMB(ce->cursor_param);
			}
			break;
		case T_NextValueExpr:
			{
				NextValueExpr *nve = (NextValueExpr *) node;

				pgq_JumbleOid(jstate, pgq_Seq, nve->seqid);
				pgq_JumbleOid(jstate, pgq_Typ, nve->typeId);
			}
			break;
		case T_InferenceElem:
			{
				InferenceElem *ie = (InferenceElem *) node;

				pgq_JumbleOid(jstate, pgq_Coll, ie->infercollid);
				PGQ_APP_JUMB(ie->inferopclass);
				pgq_JumbleExpr(jstate, ie->expr);
			}
			break;
		case T_TargetEntry:
			{
				TargetEntry *tle = (TargetEntry *) node;

				PGQ_APP_JUMB(tle->resno);
				PGQ_APP_JUMB(tle->ressortgroupref);
				pgq_JumbleExpr(jstate, (Node *) tle->expr);
			}
			break;
		case T_RangeTblRef:
			{
				RangeTblRef *rtr = (RangeTblRef *) node;

				PGQ_APP_JUMB(rtr->rtindex);
			}
			break;
		case T_JoinExpr:
			{
				JoinExpr   *join = (JoinExpr *) node;

				PGQ_APP_JUMB(join->jointype);
				PGQ_APP_JUMB(join->isNatural);
				PGQ_APP_JUMB(join->rtindex);
				pgq_JumbleExpr(jstate, join->larg);
				pgq_JumbleExpr(jstate, join->rarg);
				pgq_JumbleExpr(jstate, join->quals);
			}
			break;
		case T_FromExpr:
			{
				FromExpr   *from = (FromExpr *) node;

				pgq_JumbleExpr(jstate, (Node *) from->fromlist);
				pgq_JumbleExpr(jstate, from->quals);
			}
			break;
		case T_OnConflictExpr:
			{
				OnConflictExpr *conf = (OnConflictExpr *) node;

				PGQ_APP_JUMB(conf->action);
				pgq_JumbleExpr(jstate, (Node *) conf->arbiterElems);
				pgq_JumbleExpr(jstate, conf->arbiterWhere);
				pgq_JumbleExpr(jstate, (Node *) conf->onConflictSet);
				pgq_JumbleExpr(jstate, conf->onConflictWhere);
				PGQ_APP_JUMB(conf->constraint);
				PGQ_APP_JUMB(conf->exclRelIndex);
				pgq_JumbleExpr(jstate, (Node *) conf->exclRelTlist);
			}
			break;
		case T_List:
			foreach(temp, (List *) node)
			{
				pgq_JumbleExpr(jstate, (Node *) lfirst(temp));
			}
			break;
		case T_IntList:
			foreach(temp, (List *) node)
			{
				PGQ_APP_JUMB(lfirst_int(temp));
			}
			break;
		case T_SortGroupClause:
			{
				SortGroupClause *sgc = (SortGroupClause *) node;

				PGQ_APP_JUMB(sgc->tleSortGroupRef);
				PGQ_APP_JUMB(sgc->eqop);
				PGQ_APP_JUMB(sgc->sortop);
				PGQ_APP_JUMB(sgc->nulls_first);
			}
			break;
		case T_GroupingSet:
			{
				GroupingSet *gsnode = (GroupingSet *) node;

				pgq_JumbleExpr(jstate, (Node *) gsnode->content);
			}
			break;
		case T_WindowClause:
			{
				WindowClause *wc = (WindowClause *) node;

				PGQ_APP_JUMB(wc->winref);
				PGQ_APP_JUMB(wc->frameOptions);
				pgq_JumbleExpr(jstate, (Node *) wc->partitionClause);
				pgq_JumbleExpr(jstate, (Node *) wc->orderClause);
				pgq_JumbleExpr(jstate, wc->startOffset);
				pgq_JumbleExpr(jstate, wc->endOffset);
			}
			break;
		case T_CommonTableExpr:
			{
				CommonTableExpr *cte = (CommonTableExpr *) node;

				/* we store the string name because RTE_CTE RTEs need it */
				PGQ_APP_JUMB_STRING(cte->ctename);
				PGQ_APP_JUMB(cte->ctematerialized);
				pgq_JumbleQueryInternal(jstate, castNode(Query, cte->ctequery));
			}
			break;
		case T_SetOperationStmt:
			{
				SetOperationStmt *setop = (SetOperationStmt *) node;

				PGQ_APP_JUMB(setop->op);
				PGQ_APP_JUMB(setop->all);
				pgq_JumbleExpr(jstate, setop->larg);
				pgq_JumbleExpr(jstate, setop->rarg);
			}
			break;
		case T_RangeTblFunction:
			{
				RangeTblFunction *rtfunc = (RangeTblFunction *) node;

				pgq_JumbleExpr(jstate, rtfunc->funcexpr);
			}
			break;
		case T_TableFunc:
			{
				TableFunc  *tablefunc = (TableFunc *) node;

				pgq_JumbleExpr(jstate, tablefunc->docexpr);
				pgq_JumbleExpr(jstate, tablefunc->rowexpr);
				pgq_JumbleExpr(jstate, (Node *) tablefunc->colexprs);
			}
			break;
		case T_TableSampleClause:
			{
				TableSampleClause *tsc = (TableSampleClause *) node;

				PGQ_APP_JUMB(tsc->tsmhandler);
				pgq_JumbleExpr(jstate, (Node *) tsc->args);
				pgq_JumbleExpr(jstate, (Node *) tsc->repeatable);
			}
			break;
		default:
			/* Only a warning, since we can stumble along anyway */
			elog(WARNING, "unrecognized node type: %d",
				 (int) nodeTag(node));
			break;
	}
}

static JumbleState *
pgq_JumbleQuery(Query *query, const char *querytext)
{
	JumbleState *jstate = NULL;
	if (query->utilityStmt)
	{
		query->queryId = pgq_compute_utility_queryid(querytext,
												 query->stmt_location,
												 query->stmt_len);
	}
	else
	{
		jstate = (JumbleState *) palloc(sizeof(JumbleState));

		/* Set up workspace for query jumbling */
		jstate->jumble = (unsigned char *) palloc(JUMBLE_SIZE);
		jstate->jumble_len = 0;
		jstate->clocations_buf_size = 32;
		jstate->clocations = (LocationLen *)
			palloc(jstate->clocations_buf_size * sizeof(LocationLen));
		jstate->clocations_count = 0;
		jstate->highest_extern_param_id = 0;

		/* Compute query ID and mark the Query node with it */
		pgq_JumbleQueryInternal(jstate, query);
		query->queryId = DatumGetUInt64(hash_any_extended(jstate->jumble,
														  jstate->jumble_len,
														  0));

		/*
		 * If we are unlucky enough to get a hash of zero, use 1 instead, to
		 * prevent confusion with the utility-statement case.
		 */
		if (query->queryId == UINT64CONST(0))
			query->queryId = UINT64CONST(1);
	}

	return jstate;
}

static void
pgq_JumbleOid(JumbleState *jstate, pgqKind kind, Oid oid)
{
	switch (kind)
	{
		case pgq_Rel:
			if (pgq_use_names)
			{
				PGQ_APP_JUMB_STRING(get_rel_name(oid));
				if (!pgq_ignore_schema)
				{
					elog(WARNING, "!ignore schema");
					PGQ_APP_JUMB_STRING(get_namespace_name(get_rel_namespace(oid)));
				}
			}
			else
				PGQ_APP_JUMB(oid);
			break;
		case pgq_Func:
			if (pgq_use_names)
			{
				PGQ_APP_JUMB_STRING(get_func_name(oid));
				if (!pgq_ignore_schema)
					PGQ_APP_JUMB_STRING(get_namespace_name(get_func_namespace(oid)));
			}
			else
				PGQ_APP_JUMB(oid);
			break;
		case pgq_Seq:
			if (pgq_use_names)
			{
				PGQ_APP_JUMB_STRING(get_rel_name(oid));
				if (!pgq_ignore_schema)
					PGQ_APP_JUMB_STRING(get_namespace_name(get_rel_namespace(oid)));
			}
			else
				PGQ_APP_JUMB(oid);
			break;
		case pgq_Coll:
			if (pgq_use_names && OidIsValid(oid))
			{
				HeapTuple tp;
				char   *collname;
				Oid		collnamespace;

				tp = SearchSysCache1(COLLOID, ObjectIdGetDatum(oid));
				if (HeapTupleIsValid(tp))
				{
					Form_pg_collation colltup = (Form_pg_collation) GETSTRUCT(tp);

					collname = pstrdup(NameStr(colltup->collname));
					collnamespace = colltup->collnamespace;
					ReleaseSysCache(tp);
				}
				else
					elog(ERROR, "cache lookup failed for collation %u", oid);

				PGQ_APP_JUMB_STRING(collname);
				if (!pgq_ignore_schema)
					PGQ_APP_JUMB_STRING(get_namespace_name(collnamespace));
			}
			else
				PGQ_APP_JUMB(oid);
			break;
		case pgq_Typ:
			if (pgq_use_names)
			{
				HeapTuple	tp;
				char	   *typname;
				Oid			typnamespace;

				tp = SearchSysCache1(TYPEOID, ObjectIdGetDatum(oid));
				if (HeapTupleIsValid(tp))
				{
					Form_pg_type typtup = (Form_pg_type) GETSTRUCT(tp);
					typname = pstrdup(NameStr(typtup->typname));
					typnamespace = typtup->typnamespace;
				}
				elog(ERROR, "cache lookup failed for type %u", oid);

				PGQ_APP_JUMB_STRING(typname);
				if (!pgq_ignore_schema)
					PGQ_APP_JUMB_STRING(get_namespace_name(typnamespace));
			}
			else
				PGQ_APP_JUMB(oid);
			break;
		default:
			elog(ERROR, "pg_queryid: unexpected kind %d", kind);
	}
}

/*
 * pgq_JumbleQueryInternal: Selectively serialize the query tree, appending
 * significant data to the "query jumble" while ignoring nonsignificant data.
 *
 * Rule of thumb for what to include is that we should ignore anything not
 * semantically significant (such as alias names) as well as anything that can
 * be deduced from child nodes (else we'd just be double-hashing that piece
 * of information).
 */
static bool
pgq_JumbleQueryInternal(JumbleState *jstate, Query *query)
{
	Assert(IsA(query, Query));
	Assert(query->utilityStmt == NULL);

	PGQ_APP_JUMB(query->commandType);
	/* resultRelation is usually predictable from commandType */
	pgq_JumbleExpr(jstate, (Node *) query->cteList);
	pgq_JumbleRangeTable(jstate, query->rtable);
	pgq_JumbleExpr(jstate, (Node *) query->jointree);
	pgq_JumbleExpr(jstate, (Node *) query->targetList);
	pgq_JumbleExpr(jstate, (Node *) query->onConflict);
	pgq_JumbleExpr(jstate, (Node *) query->returningList);
	pgq_JumbleExpr(jstate, (Node *) query->groupClause);
	pgq_JumbleExpr(jstate, (Node *) query->groupingSets);
	pgq_JumbleExpr(jstate, query->havingQual);
	pgq_JumbleExpr(jstate, (Node *) query->windowClause);
	pgq_JumbleExpr(jstate, (Node *) query->distinctClause);
	pgq_JumbleExpr(jstate, (Node *) query->sortClause);
	pgq_JumbleExpr(jstate, query->limitOffset);
	pgq_JumbleExpr(jstate, query->limitCount);
	pgq_JumbleRowMarks(jstate, query->rowMarks);
	pgq_JumbleExpr(jstate, query->setOperations);

	return false;
}

/*
 * Jumble a range table
 */
static bool
pgq_JumbleRangeTable(JumbleState *jstate, List *rtable)
{
	ListCell   *lc;

	foreach(lc, rtable)
	{
		RangeTblEntry *rte = lfirst_node(RangeTblEntry, lc);

		PGQ_APP_JUMB(rte->rtekind);
		switch (rte->rtekind)
		{
			case RTE_RELATION:
				pgq_JumbleOid(jstate, pgq_Rel, rte->relid);
				pgq_JumbleExpr(jstate, (Node *) rte->tablesample);
				break;
			case RTE_SUBQUERY:
				pgq_JumbleQueryInternal(jstate, rte->subquery);
				break;
			case RTE_JOIN:
				PGQ_APP_JUMB(rte->jointype);
				break;
			case RTE_FUNCTION:
				pgq_JumbleExpr(jstate, (Node *) rte->functions);
				break;
			case RTE_TABLEFUNC:
				pgq_JumbleExpr(jstate, (Node *) rte->tablefunc);
				break;
			case RTE_VALUES:
				pgq_JumbleExpr(jstate, (Node *) rte->values_lists);
				break;
			case RTE_CTE:

				/*
				 * Depending on the CTE name here isn't ideal, but it's the
				 * only info we have to identify the referenced WITH item.
				 */
				PGQ_APP_JUMB_STRING(rte->ctename);
				PGQ_APP_JUMB(rte->ctelevelsup);
				break;
			case RTE_NAMEDTUPLESTORE:
				PGQ_APP_JUMB_STRING(rte->enrname);
				break;
			case RTE_RESULT:
				break;
			default:
				elog(ERROR, "unrecognized RTE kind: %d", (int) rte->rtekind);
				break;
		}
	}

	return false;
}

/*
 * Jumble a rowMarks list
 */
static void
pgq_JumbleRowMarks(JumbleState *jstate, List *rowMarks)
{
	ListCell   *lc;

	foreach(lc, rowMarks)
	{
		RowMarkClause *rowmark = lfirst_node(RowMarkClause, lc);

		if (!rowmark->pushedDown)
		{
			PGQ_APP_JUMB(rowmark->rti);
			PGQ_APP_JUMB(rowmark->strength);
			PGQ_APP_JUMB(rowmark->waitPolicy);
		}
	}
}

/*
 * Record location of constant within query string of query tree
 * that is currently being walked.
 */
static void
pgq_RecordConstLocation(JumbleState *jstate, int location)
{
	/* -1 indicates unknown or undefined location */
	if (location >= 0)
	{
		/* enlarge array if needed */
		if (jstate->clocations_count >= jstate->clocations_buf_size)
		{
			jstate->clocations_buf_size *= 2;
			jstate->clocations = (LocationLen *)
				repalloc(jstate->clocations,
						 jstate->clocations_buf_size *
						 sizeof(LocationLen));
		}
		jstate->clocations[jstate->clocations_count].location = location;
		/* initialize lengths to -1 to simplify third-party module usage */
		jstate->clocations[jstate->clocations_count].length = -1;
		jstate->clocations_count++;
	}
}

/*
 * SQL wrapper to compute a given query's queryid.
 */
Datum
pg_queryid(PG_FUNCTION_ARGS)
{
	char *query_string;
	List *parsetree_list;
	RawStmt *parsetree;
	ParseState *pstate;
	Query *query;

	query_string = TextDatumGetCString(PG_GETARG_TEXT_P(0));

	parsetree_list = pg_parse_query(query_string);
	if (list_length(parsetree_list) != 1)
		elog(ERROR, "You can only compute the queryid of a single statement");

	parsetree = linitial_node(RawStmt, parsetree_list);

	pstate = make_parsestate(NULL);
	pstate->p_sourcetext = query_string;
	pstate->p_queryEnv = NULL;
	query = transformTopLevelStmt(pstate, parsetree);

	if (is_spl)
		(void) pgq_JumbleQuery(query, query_string);
	else if (compute_query_id)
		(void) JumbleQuery(query, query_string);

	PG_RETURN_INT64(query->queryId);
}
