// Derived from Inferno utils/6c/swt.c
// http://code.google.com/p/inferno-os/source/browse/utils/6c/swt.c
//
//	Copyright © 1994-1999 Lucent Technologies Inc.  All rights reserved.
//	Portions Copyright © 1995-1997 C H Forsyth (forsyth@terzarima.net)
//	Portions Copyright © 1997-1999 Vita Nuova Limited
//	Portions Copyright © 2000-2007 Vita Nuova Holdings Limited (www.vitanuova.com)
//	Portions Copyright © 2004,2006 Bruce Ellis
//	Portions Copyright © 2005-2007 C H Forsyth (forsyth@terzarima.net)
//	Revisions Copyright © 2000-2007 Lucent Technologies Inc. and others
//	Portions Copyright © 2009 The Go Authors.  All rights reserved.
//
// Permission is hereby granted, free of charge, to any person obtaining a copy
// of this software and associated documentation files (the "Software"), to deal
// in the Software without restriction, including without limitation the rights
// to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
// copies of the Software, and to permit persons to whom the Software is
// furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included in
// all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.  IN NO EVENT SHALL THE
// AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
// LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
// OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
// THE SOFTWARE.

#include "gg.h"

void
dumpobj(void)
{
	Plist *pl;
	Prog *p;
	Dcl *d;
	Sym *s;
	Node *n;
	struct { Sym *sym; short type; } h[NSYM];
	int sf, st, t, sym;
	Node n1;

	// add nil plist w AEND
	newplist();

	bout = Bopen(outfile, OWRITE);
	if(bout == nil)
		fatal("cant open %s", outfile);

	Bprint(bout, "amd64\n");
	Bprint(bout, "  exports automatically generated from\n");
	Bprint(bout, "  %s in package \"%s\"\n", curio.infile, package);
	dumpexport();
	Bprint(bout, "\n!\n");

	outhist(bout);

	// add globals
	nodconst(&n1, types[TINT32], 0);
	for(d=externdcl; d!=D; d=d->forw) {
		if(d->op != ONAME)
			continue;

		s = d->dsym;
		if(s == S)
			fatal("external nil");
		n = d->dnode;
		if(n == N || n->type == T)
			fatal("external %S nil\n", s);

		if(n->class == PFUNC)
			continue;

		dowidth(n->type);
		mpmovecfix(n1.val.u.xval, n->type->width);

		p = pc;
		gins(AGLOBL, s->oname, &n1);
		p->lineno = s->oname->lineno;
	}

	dumpstrings();
	dumpsignatures();

	for(sym=0; sym<NSYM; sym++) {
		h[sym].sym = S;
		h[sym].type = 0;
	}
	sym = 1;

	// fix up pc
	pcloc = 0;
	for(pl=plist; pl!=nil; pl=pl->link) {
		for(p=pl->firstpc; p!=P; p=p->link) {
			p->loc = pcloc;
			pcloc++;
		}
	}

	// put out functions
	for(pl=plist; pl!=nil; pl=pl->link) {

		if(debug['S']) {
			s = S;
			if(pl->name != N)
				s = pl->name->sym;
			print("\n--- prog list \"%S\" ---\n", s);
			for(p=pl->firstpc; p!=P; p=p->link)
				print("%P\n", p);
		}

		for(p=pl->firstpc; p!=P; p=p->link) {
		jackpot:
			sf = 0;
			s = p->from.sym;
			while(s != S) {
				sf = s->sym;
				if(sf < 0 || sf >= NSYM)
					sf = 0;
				t = p->from.type;
				if(t == D_ADDR)
					t = p->from.index;
				if(h[sf].type == t)
				if(h[sf].sym == s)
					break;
				s->sym = sym;
				zname(bout, s, t);
				h[sym].sym = s;
				h[sym].type = t;
				sf = sym;
				sym++;
				if(sym >= NSYM)
					sym = 1;
				break;
			}
			st = 0;
			s = p->to.sym;
			while(s != S) {
				st = s->sym;
				if(st < 0 || st >= NSYM)
					st = 0;
				t = p->to.type;
				if(t == D_ADDR)
					t = p->to.index;
				if(h[st].type == t)
				if(h[st].sym == s)
					break;
				s->sym = sym;
				zname(bout, s, t);
				h[sym].sym = s;
				h[sym].type = t;
				st = sym;
				sym++;
				if(sym >= NSYM)
					sym = 1;
				if(st == sf)
					goto jackpot;
				break;
			}
			Bputc(bout, p->as);
			Bputc(bout, p->as>>8);
			Bputc(bout, p->lineno);
			Bputc(bout, p->lineno>>8);
			Bputc(bout, p->lineno>>16);
			Bputc(bout, p->lineno>>24);
			zaddr(bout, &p->from, sf);
			zaddr(bout, &p->to, st);
		}
	}
	Bterm(bout);
}

void
Bputdot(Biobuf *b)
{
	// put out middle dot ·
	Bputc(b, 0xc2);
	Bputc(b, 0xb7);
}

void
zname(Biobuf *b, Sym *s, int t)
{
	char *n;

	Bputc(b, ANAME);	/* as */
	Bputc(b, ANAME>>8);	/* as */
	Bputc(b, t);		/* type */
	Bputc(b, s->sym);	/* sym */

	for(n=s->opackage; *n; n++)
		Bputc(b, *n);
	Bputdot(b);
	for(n=s->name; *n; n++)
		Bputc(b, *n);
	Bputc(b, 0);
}

void
zaddr(Biobuf *b, Addr *a, int s)
{
	int32 l;
	int i, t;
	char *n;
	Ieee e;

	t = 0;
	if(a->index != D_NONE || a->scale != 0)
		t |= T_INDEX;
	if(s != 0)
		t |= T_SYM;

	switch(a->type) {

	case D_BRANCH:
		a->offset = a->branch->loc;

	default:
		t |= T_TYPE;

	case D_NONE:
		if(a->offset != 0) {
			t |= T_OFFSET;
			l = a->offset;
			if((vlong)l != a->offset)
				t |= T_64;
		}
		break;
	case D_FCONST:
		t |= T_FCONST;
		break;
	case D_SCONST:
		t |= T_SCONST;
		break;
	}
	Bputc(b, t);

	if(t & T_INDEX) {	/* implies index, scale */
		Bputc(b, a->index);
		Bputc(b, a->scale);
	}
	if(t & T_OFFSET) {	/* implies offset */
		l = a->offset;
		Bputc(b, l);
		Bputc(b, l>>8);
		Bputc(b, l>>16);
		Bputc(b, l>>24);
		if(t & T_64) {
			l = a->offset>>32;
			Bputc(b, l);
			Bputc(b, l>>8);
			Bputc(b, l>>16);
			Bputc(b, l>>24);
		}
	}
	if(t & T_SYM)		/* implies sym */
		Bputc(b, s);
	if(t & T_FCONST) {
		ieeedtod(&e, a->dval);
		l = e.l;
		Bputc(b, l);
		Bputc(b, l>>8);
		Bputc(b, l>>16);
		Bputc(b, l>>24);
		l = e.h;
		Bputc(b, l);
		Bputc(b, l>>8);
		Bputc(b, l>>16);
		Bputc(b, l>>24);
		return;
	}
	if(t & T_SCONST) {
		n = a->sval;
		for(i=0; i<NSNAME; i++) {
			Bputc(b, *n);
			n++;
		}
		return;
	}
	if(t & T_TYPE)
		Bputc(b, a->type);
}

void
outhist(Biobuf *b)
{
	Hist *h;
	char *p, *q, *op;
	Prog pg;
	int n;

	pg = zprog;
	pg.as = AHISTORY;
	for(h = hist; h != H; h = h->link) {
		p = h->name;
		op = 0;

		if(p && p[0] != '/' && h->offset == 0 && pathname && pathname[0] == '/') {
			op = p;
			p = pathname;
		}

		while(p) {
			q = utfrune(p, '/');
			if(q) {
				n = q-p;
				if(n == 0)
					n = 1;		// leading "/"
				q++;
			} else {
				n = strlen(p);
				q = 0;
			}
			if(n) {
				Bputc(b, ANAME);
				Bputc(b, ANAME>>8);
				Bputc(b, D_FILE);
				Bputc(b, 1);
				Bputc(b, '<');
				Bwrite(b, p, n);
				Bputc(b, 0);
			}
			p = q;
			if(p == 0 && op) {
				p = op;
				op = 0;
			}
		}

		pg.lineno = h->line;
		pg.to.type = zprog.to.type;
		pg.to.offset = h->offset;
		if(h->offset)
			pg.to.type = D_CONST;

		Bputc(b, pg.as);
		Bputc(b, pg.as>>8);
		Bputc(b, pg.lineno);
		Bputc(b, pg.lineno>>8);
		Bputc(b, pg.lineno>>16);
		Bputc(b, pg.lineno>>24);
		zaddr(b, &pg.from, 0);
		zaddr(b, &pg.to, 0);
	}
}

void
ieeedtod(Ieee *ieee, double native)
{
	double fr, ho, f;
	int exp;

	if(native < 0) {
		ieeedtod(ieee, -native);
		ieee->h |= 0x80000000L;
		return;
	}
	if(native == 0) {
		ieee->l = 0;
		ieee->h = 0;
		return;
	}
	fr = frexp(native, &exp);
	f = 2097152L;		/* shouldnt use fp constants here */
	fr = modf(fr*f, &ho);
	ieee->h = ho;
	ieee->h &= 0xfffffL;
	ieee->h |= (exp+1022L) << 20;
	f = 65536L;
	fr = modf(fr*f, &ho);
	ieee->l = ho;
	ieee->l <<= 16;
	ieee->l |= (int32)(fr*f);
}

void
datastring(char *s, int len)
{
	int w;
	Prog *p;
	Addr ac, ao;

	// string
	memset(&ao, 0, sizeof(ao));
	ao.type = D_STATIC;
	ao.index = D_NONE;
	ao.etype = TINT32;
	ao.sym = symstringo;
	ao.offset = 0;		// fill in

	// constant
	memset(&ac, 0, sizeof(ac));
	ac.type = D_CONST;
	ac.index = D_NONE;
	ac.offset = 0;		// fill in

	for(w=0; w<len; w+=8) {
		p = pc;
		gins(ADATA, N, N);

		// .stringo<>+oo, [NSNAME], $"xxx"
		p->from = ao;
		p->from.offset = stringo;

		p->from.scale = NSNAME;
		if(w+8 > len)
			p->from.scale = len-w;

		p->to = ac;
		p->to.type = D_SCONST;
		p->to.offset = len;
		memmove(p->to.sval, s+w, p->from.scale);
		stringo += p->from.scale;
	}
}

void
dumpstrings(void)
{
	Pool *l;
	Prog *p;
	Addr ac, ao;
	int32 wi;

	if(poolist == nil)
		return;

	memset(&ac, 0, sizeof(ac));
	memset(&ao, 0, sizeof(ao));

	// constant
	ac.type = D_CONST;
	ac.index = D_NONE;
	ac.offset = 0;			// fill in

	// string len+ptr
	ao.type = D_STATIC;
	ao.index = D_NONE;
	ao.etype = TINT32;
	ao.sym = symstringo;
	ao.offset = 0;			// fill in

	wi = types[TINT32]->width;

	// lay out (count+string)
	for(l=poolist; l!=nil; l=l->link) {

		p = pc;
		gins(ADATA, N, N);

		// .stringo<>+xx, wi, $len
		stringo = rnd(stringo, wi);
		p->from = ao;
		p->from.offset = stringo;
		p->from.scale = wi;
		p->to = ac;
		p->to.offset = l->sval->len;
		stringo += wi;

		datastring(l->sval->s, l->sval->len);
	}
}

static int
sigcmp(Sig *a, Sig *b)
{
	return strcmp(a->name, b->name);
}

static	Addr	at, ao, ac, ad;
static	int	wi, ws, ot;

void
ginsatoa(int fscale, int toffset)
{
	Prog *p;

	p = pc;
	ot = rnd(ot, fscale);

	gins(ADATA, N, N);
	p->from = at;
	p->from.offset = ot;
	p->from.scale = fscale;
	p->to = ao;
	p->to.offset = toffset;
	ot += fscale;
}

void
gensatac(int fscale, int toffset)
{
	Prog *p;

	p = pc;
	ot = rnd(ot, fscale);

	gins(ADATA, N, N);
	p->from = at;
	p->from.offset = ot;
	p->from.scale = fscale;
	p->to = ac;
	p->to.offset = toffset;
	ot += fscale;
}

void
gensatad(Sym *s)
{
	Prog *p;

	p = pc;
	ot = rnd(ot, widthptr);

	gins(ADATA, N, N);
	p->from = at;
	p->from.offset = ot;
	p->from.scale = widthptr;
	p->to = ad;
	p->to.sym = s;
	ot += widthptr;
}

void
genembedtramp(Type *t, Sig *b)
{
	Sym *e;
	int c, d, o;
	Prog *p;
	Type *f;

	e = lookup(b->name);
	for(d=0; d<nelem(dotlist); d++) {
		c = adddot1(e, t, d, nil);
		if(c == 1)
			goto out;
	}
	fatal("genembedtramp %T.%s", t, b->name);

out:
	if(d == 0)
		return;

//	print("genembedtramp %d\n", d);
//	print("	t    = %lT\n", t);
//	print("	name = %s\n", b->name);
//	print("	sym  = %S\n", b->sym);
//	print("	hash = 0x%ux\n", b->hash);

	newplist()->name = newname(b->sym);

	//TEXT	main·S_test2(SB),7,$0
	p = pc;
	gins(ATEXT, N, N);
	p->from.type = D_EXTERN;
	p->from.sym = b->sym;
	p->to.type = D_CONST;
	p->to.offset = 0;
	p->from.scale = 7;
//print("1. %P\n", p);

	//MOVQ	8(SP), AX
	p = pc;
	gins(AMOVQ, N, N);
	p->from.type = D_INDIR+D_SP;
	p->from.offset = 8;
	p->to.type = D_AX;
//print("2. %P\n", p);

	o = 0;
	for(c=d-1; c>=0; c--) {
		f = dotlist[c].field;
		o += f->width;
		if(!isptr[f->type->etype])
			continue;
		//MOVQ	o(AX), AX
		p = pc;
		gins(AMOVQ, N, N);
		p->from.type = D_INDIR+D_AX;
		p->from.offset = o;
		p->to.type = D_AX;
//print("3. %P\n", p);
		o = 0;
	}
	if(o != 0) {
		//ADDQ	$XX, AX
		p = pc;
		gins(AADDQ, N, N);
		p->from.type = D_CONST;
		p->from.offset = o;
		p->to.type = D_AX;
//print("4. %P\n", p);
	}

	//MOVQ	AX, 8(SP)
	p = pc;
	gins(AMOVQ, N, N);
	p->from.type = D_AX;
	p->to.type = D_INDIR+D_SP;
	p->to.offset = 8;
//print("5. %P\n", p);

	f = dotlist[0].field;
	//JMP	main·*Sub_test2(SB)
	if(isptr[f->type->etype])
		f = f->type;
	p = pc;
	gins(AJMP, N, N);
	p->to.type = D_EXTERN;
	p->to.sym = methodsym(lookup(b->name), ptrto(f->type));
//print("6. %P\n", p);

	pc->as = ARET;	// overwrite AEND
}

/*
 * Add DATA for signature s.
 *	progt - type in program
 *	ifacet - type stored in interface (==progt if small, ==ptrto(progt) if large)
 *	rcvrt - type used as method interface.  eqtype(ifacet, rcvrt) is always true,
 *		but ifacet might have a name that rcvrt does not.
 *	methodt - type with methods hanging off it (progt==*methodt sometimes)
 *
 * memory layout is Sigt struct from iface.c:
 *	struct	Sigt
 *	{
 *		byte*	name;                   // name of basic type
 *		Sigt*	link;			// for linking into hash tables
 *		uint32	thash;                  // hash of type
 *		uint32	mhash;                  // hash of methods
 *		uint16	width;			// width of base type in bytes
 *		uint16	alg;			// algorithm
 *		uint32	pad;
 *		struct {
 *			byte*	fname;
 *			uint32	fhash;		// hash of type
 *			uint32	offset;		// offset of substruct
 *			void	(*fun)(void);
 *		} meth[1];			// one or more - last name is nil
 *	};
 */

void
dumpsigt(Type *progt, Type *ifacet, Type *rcvrt, Type *methodt, Sym *s)
{
	Type *f;
	int o;
	Sig *a, *b;
	Prog *p;
	char buf[NSYMB];
	Type *this;
	Iter savet;
	Prog *oldlist;
	Sym *method;
	uint32 sighash;

	at.sym = s;

	a = nil;
	o = 0;
	oldlist = nil;
	sighash = typehash(progt, 1, 0);
	for(f=methodt->method; f!=T; f=f->down) {
		if(f->type->etype != TFUNC)
			continue;

		if(f->etype != TFIELD)
			fatal("dumpsignatures: not field");

		method = f->sym;
		if(method == nil)
			continue;

		b = mal(sizeof(*b));
		b->link = a;
		a = b;

		a->name = method->name;
		a->hash = PRIME8*stringhash(a->name) + PRIME9*typehash(f->type, 0, 0);
		if(!exportname(a->name))
			a->hash += PRIME10*stringhash(package);
		a->perm = o;
		a->sym = methodsym(method, rcvrt);

		sighash = sighash*100003 + a->hash;

		if(!a->sym->siggen) {
			a->sym->siggen = 1;
			// TODO(rsc): This test is still not quite right.

			this = structfirst(&savet, getthis(f->type))->type;
			if(isptr[this->etype] != isptr[ifacet->etype]) {
				if(oldlist == nil)
					oldlist = pc;

				// indirect vs direct mismatch
				Sym *oldname, *newname;
				Type *oldthis, *newthis;

				newthis = ifacet;
				if(isptr[newthis->etype])
					oldthis = ifacet->type;
				else
					oldthis = ptrto(ifacet);
				newname = a->sym;
				oldname = methodsym(method, oldthis);
				genptrtramp(method, oldname, oldthis, f->type, newname, newthis);
			} else
			if(f->embedded) {
				// TODO(rsc): only works for pointer receivers
				if(oldlist == nil)
					oldlist = pc;
				genembedtramp(ifacet, a);
			}
		}
		o++;
	}

	// restore data output
	if(oldlist) {
		// old list ended with AEND; change to ANOP
		// so that the trampolines that follow can be found.
		oldlist->as = ANOP;

		// start new data list
		newplist();
	}

	a = lsort(a, sigcmp);
	ot = 0;
	ot = rnd(ot, maxround);	// base structure

	// base of type signature contains parameters
	ginsatoa(widthptr, stringo);		// name
	ot = rnd(ot, widthptr)+widthptr;	// skip link
	gensatac(wi, typehash(progt, 1, 0));	// thash
	gensatac(wi, sighash);			// mhash
	gensatac(ws, progt->width);		// width
	gensatac(ws, algtype(progt));		// algorithm

	snprint(buf, sizeof buf, "%#T", progt);
	datastring(buf, strlen(buf)+1);

	for(b=a; b!=nil; b=b->link) {
		ot = rnd(ot, maxround);		// base of substructure
		ginsatoa(widthptr, stringo);	// field name
		gensatac(wi, b->hash);		// hash
		gensatac(wi, 0);		// offset
		gensatad(b->sym);		// &method

		datastring(b->name, strlen(b->name)+1);
	}

	// nil field name at end
	ot = rnd(ot, maxround);
	gensatac(widthptr, 0);

	// set DUPOK to allow other .6s to contain
	// the same signature.  only one will be chosen.
	// should only happen for empty signatures
	p = pc;
	gins(AGLOBL, N, N);
	p->from = at;
	if(a == nil)
		p->from.scale = DUPOK;
	p->to = ac;
	p->to.offset = ot;
}

/*
 * memory layout is Sigi struct from iface.c:
 *	struct	Sigi
 *	{
 *		byte*	name;
 *		uint32	hash;
 *		uint32	size;			// number of methods
 *		struct {
 *			byte*	fname;
 *			uint32	fhash;
 *			uint32	perm;		// location of fun in Sigt
 *		} meth[1];			// [size+1] - last name is nil
 *	};
 */
void
dumpsigi(Type *t, Sym *s)
{
	Type *f;
	Sym *s1;
	int o;
	Sig *a, *b;
	Prog *p;
	char buf[NSYMB];
	uint32 sighash;

	at.sym = s;

	a = nil;
	o = 0;
	sighash = 0;
	for(f=t->type; f!=T; f=f->down) {
		if(f->type->etype != TFUNC)
			continue;

		if(f->etype != TFIELD)
			fatal("dumpsignatures: not field");

		s1 = f->sym;
		if(s1 == nil)
			continue;

		b = mal(sizeof(*b));
		b->link = a;
		a = b;

		a->name = s1->name;
		a->hash = PRIME8*stringhash(a->name) + PRIME9*typehash(f->type, 0, 0);
		if(!exportname(a->name))
			a->hash += PRIME10*stringhash(package);
		a->perm = o;
		a->sym = methodsym(f->sym, t);
		a->offset = 0;

		sighash = sighash*100003 + a->hash;

		o++;
	}

	a = lsort(a, sigcmp);
	ot = 0;
	ot = rnd(ot, maxround);	// base structure

	// sigi[0].name = ""
	ginsatoa(widthptr, stringo);

	// save type name for runtime error message.
	snprint(buf, sizeof buf, "%#T", t);
	datastring(buf, strlen(buf)+1);

	// first field of an interface signature
	// contains the count and is not a real entry

	// sigi[0].hash = sighash
	gensatac(wi, sighash);

	// sigi[0].offset = count
	o = 0;
	for(b=a; b!=nil; b=b->link)
		o++;
	gensatac(wi, o);

	for(b=a; b!=nil; b=b->link) {
//print("	%s\n", b->name);
		ot = rnd(ot, maxround);	// base structure

		// sigx[++].name = "fieldname"
		ginsatoa(widthptr, stringo);

		// sigx[++].hash = hashcode
		gensatac(wi, b->hash);

		// sigi[++].perm = mapped offset of method
		gensatac(wi, b->perm);

		datastring(b->name, strlen(b->name)+1);
	}

	// nil field name at end
	ot = rnd(ot, maxround);
	gensatac(widthptr, 0);

	p = pc;
	gins(AGLOBL, N, N);
	p->from = at;
	p->from.scale = DUPOK;
	p->to = ac;
	p->to.offset = ot;
}

void
dumpsignatures(void)
{
	int et;
	Dcl *d, *x;
	Type *t, *progt, *methodt, *ifacet, *rcvrt;
	Sym *s;
	Prog *p;

	memset(&at, 0, sizeof(at));
	memset(&ao, 0, sizeof(ao));
	memset(&ac, 0, sizeof(ac));
	memset(&ad, 0, sizeof(ad));

	wi = types[TINT32]->width;
	ws = types[TINT16]->width;

	// sig structure
	at.type = D_EXTERN;
	at.index = D_NONE;
	at.sym = S;			// fill in
	at.offset = 0;			// fill in

	// $string
	ao.type = D_ADDR;
	ao.index = D_STATIC;
	ao.etype = TINT32;
	ao.sym = symstringo;
	ao.offset = 0;			// fill in

	// constant
	ac.type = D_CONST;
	ac.index = D_NONE;
	ac.offset = 0;			// fill in

	// $method
	ad.type = D_ADDR;
	ad.index = D_EXTERN;
	ad.sym = S;			// fill in
	ad.offset = 0;

	// copy externdcl list to signatlist
	for(d=externdcl; d!=D; d=d->forw) {
		if(d->op != OTYPE)
			continue;

		t = d->dtype;
		if(t == T)
			continue;

		s = signame(t);
		if(s == S)
			continue;

		x = mal(sizeof(*d));
		x->op = OTYPE;
		if(t->etype == TINTER)
			x->dtype = t;
		else
			x->dtype = ptrto(t);
		x->forw = signatlist;
		x->block = 0;
		signatlist = x;
//print("SIG = %lS %lS %lT\n", d->dsym, s, t);
	}

	// process signatlist
	for(d=signatlist; d!=D; d=d->forw) {
		if(d->op != OTYPE)
			continue;
		t = d->dtype;
		et = t->etype;
		s = signame(t);
		if(s == S)
			continue;

		// only emit one
		if(s->siggen)
			continue;
		s->siggen = 1;

		// interface is easy
		if(et == TINTER || et == TDDD) {
			if(t->sym && !t->local)
				continue;
			dumpsigi(t, s);
			continue;
		}

		// non-interface is more complex
		progt = t;
		methodt = t;
		ifacet = t;
		rcvrt = t;

		// if there's a pointer, methods are on base.
		if(isptr[methodt->etype] && methodt->type->sym != S) {
			methodt = methodt->type;
			expandmeth(methodt->sym, methodt);

			// if methodt had a name, we don't want to see
			// it in the method names that go into the sigt.
			// e.g., if
			//	type item *rat
			// then item needs its own sigt distinct from *rat,
			// but it needs to have all of *rat's methods, using
			// the *rat (not item) in the method names.
			if(rcvrt->sym != S)
				rcvrt = ptrto(methodt);
		}

		// and if ifacet is too wide, the methods
		// will see a pointer anyway.
		if(ifacet->width > 8) {
			ifacet = ptrto(progt);
			rcvrt = ptrto(progt);
		}

		// don't emit non-trivial signatures for types defined outside this file.
		// non-trivial signatures might also drag in generated trampolines,
		// and ar can't handle duplicates of the trampolines.
		// only pay attention to types with symbols, because
		// the ... structs and maybe other internal structs
		// don't get marked as local.
		if(methodt->method && methodt->sym && !methodt->local)
			continue;

//print("s=%S\n", s);
		dumpsigt(progt, ifacet, rcvrt, methodt, s);
	}

	if(stringo > 0) {
		p = pc;
		gins(AGLOBL, N, N);
		p->from = ao;
		p->to = ac;
		p->to.offset = stringo;
	}
}
