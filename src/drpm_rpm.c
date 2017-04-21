/*
    Authors:
        Matej Chalk <mchalk@redhat.com>

    Copyright (C) 2015 Red Hat

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU Lesser General Public License as published by
    the Free Software Foundation; either version 3 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public License
    along with this program.  If not, see <http://www.gnu.org/licenses/>.
*/

#include "drpm.h"
#include "drpm_private.h"

#include <stdint.h>
#include <string.h>
#include <limits.h>
#include <fcntl.h>

#ifdef	RPM5
#include <alloca.h>
#include <strings.h>
#include <rpmio.h>
#include <rpmtag.h>
typedef rpmTag	rpmTagVal;
#include <pkgio.h>
#include <rpmdb.h>
#include <rpmfi.h>
#include <rpmts.h>
#include <rpmrc.h>
#else	/* RPM5 */
#include <rpm/rpmlib.h>
#include <rpm/rpmts.h>
#include <rpm/rpmdb.h>
#endif	/* RPM5 */

#include <openssl/md5.h>

#define BUFFER_SIZE 4096

/* RFC 4880 - Section 9.4. Hash Algorithms */
#define RFC4880_HASH_ALGO_MD5 1
#define RFC4880_HASH_ALGO_SHA256 8

#define RPMSIG_PADDING(offset) PADDING((offset), 8)

#define RPMLEAD_SIZE 96

struct rpm {
    unsigned char lead[RPMLEAD_SIZE];
    Header signature;
    Header header;
    unsigned char *archive;
    size_t archive_size;
    size_t archive_offset;
    size_t archive_comp_size;
};

static void rpm_init(struct rpm *);
static void rpm_free(struct rpm *);
static int rpm_export_header(struct rpm *, unsigned char **, size_t *);
static int rpm_export_signature(struct rpm *, unsigned char **, size_t *);
static void rpm_header_unload_region(struct rpm *, rpmTagVal);
static int rpm_read_archive(struct rpm *, const char *, off_t, bool,
                            unsigned short *, MD5_CTX *, MD5_CTX *);


#ifdef	RPM5
static
const unsigned char rpm_header_magic[8] = {
        0x8e, 0xad, 0xe8, 0x01, 0x00, 0x00, 0x00, 0x00
};

#define	rpmheFree(_he)	if (_he->p.ptr) { free(_he->p.ptr); _he->p.ptr = 0; }
static
const char * headerGetString(Header h, rpmTag tag)
{
    const char * res = NULL;
    HE_t he = (HE_t) memset(alloca(sizeof(*he)), 0, sizeof(*he));
    he->tag = tag;
    if (headerGet(h, he, 0) && he->t == RPM_STRING_TYPE) {
	res = he->p.str;
	he->p.ptr = NULL;
    }
    rpmheFree(he);
    return res;
}
#define	headerGetAsString(_h, _tag)	(char *)headerGetString(_h, _tag)

static
uint64_t headerGetNumber(Header h, rpmTag tag)
{
    uint64_t res = 0;
    HE_t he = (HE_t) memset(alloca(sizeof(*he)), 0, sizeof(*he));
    he->tag = tag;
    if (headerGet(h, he, 0) && he->t == RPM_UINT32_TYPE)
	res = he->p.ui32p[0];
    rpmheFree(he);
    return res;
}

static
void * headerExport(Header h, unsigned int *bsize)
{
    size_t len = 0;
    void * blob = headerUnload(h, &len);
    if (bsize)
	*bsize = len;
    return blob;
}

#define	HEADERIMPORT_COPY	1
static
Header headerImport(void *blob, unsigned int bsize, unsigned int flags)
{
assert (bsize == 0);
assert (flags == HEADERIMPORT_COPY);
    return headerCopyLoad(blob);
}

typedef	rpmmi rpmdbMatchIterator;
#define	rpmdbSetIteratorRE(_mi, _tag, _mode, _pattern) \
		rpmmiAddPattern(_mi, _tag, _mode, _pattern)
#define	rpmdbNextIterator(_mi)	rpmmiNext(_mi)
#define	rpmdbFreeIterator(_mi)	rpmmiFree(_mi)

#endif	/* RPM5 */

void rpm_init(struct rpm *rpmst)
{
    if (rpmst == NULL)
        return;

    memset(rpmst->lead, 0, RPMLEAD_SIZE);
    rpmst->signature = NULL;
    rpmst->header = NULL;
    rpmst->archive = NULL;
    rpmst->archive_size = 0;
    rpmst->archive_offset = 0;
    rpmst->archive_comp_size = 0;
}

void rpm_free(struct rpm *rpmst)
{
    if (rpmst == NULL)
        return;

    headerFree(rpmst->signature);
    headerFree(rpmst->header);
    free(rpmst->archive);

    rpm_init(rpmst);
}

int rpm_export_signature(struct rpm *rpmst, unsigned char **bp, size_t *nbp)
{
    int error = DRPM_ERR_OK;
    unsigned char *sb = NULL;	/* signature buffer */
    unsigned nsb = 0;		/* signature buffer length */
    size_t nb = 0;		/* lead+signature+padding length */
    unsigned char padding[7] = {0};
    unsigned short padding_bytes;

    *bp = NULL;
    *nbp = 0;

    sb = headerExport(rpmst->signature, &nsb);
    if (sb == NULL) {
        return DRPM_ERR_MEMORY;
    }

    nb = sizeof(rpm_header_magic) + nsb;
    padding_bytes = RPMSIG_PADDING(nsb);
    nb += padding_bytes;

    if ((*bp = malloc(nb)) == NULL) {
        free(sb);
        return DRPM_ERR_MEMORY;
    }

    memcpy(*bp, rpm_header_magic, sizeof(rpm_header_magic));
    memcpy(*bp + sizeof(rpm_header_magic), sb, nsb);
    memcpy(*bp + sizeof(rpm_header_magic) + nsb, padding, padding_bytes);

    *nbp = nb;

    if (sb)
        free(sb);

    return error;
}

int rpm_export_header(struct rpm *rpmst, unsigned char **bp, size_t *nbp)
{
    int error = DRPM_ERR_OK;
    unsigned char *hb = NULL;	/* header buffer */
    unsigned nhb = 0;		/* header buffer length */
    size_t nb = 0;		/* magic+header length */

    *bp = NULL;
    *nbp = 0;

    hb = headerExport(rpmst->header, &nhb);
    if (hb == NULL) {
        return DRPM_ERR_MEMORY;
    }

    nb = sizeof(rpm_header_magic) + nhb;

    if ((*bp = malloc(nb)) == NULL) {
        free(hb);
        return DRPM_ERR_MEMORY;
    }

    memcpy(*bp, rpm_header_magic, sizeof(rpm_header_magic));
    memcpy(*bp + sizeof(rpm_header_magic), hb, nhb);

    *nbp = nb;

    if (hb)
        free(hb);

    return error;
}

void rpm_header_unload_region(struct rpm *rpmst, rpmTagVal tag)
{
#ifdef	RPM5
    Header h =
	(tag == RPMTAG_HEADERIMMUTABLE ? rpmst->header : rpmst->signature);
    Header nh = headerNew();
    HE_t he = (HE_t) memset(alloca(sizeof(*he)), 0, sizeof(*he));
    unsigned flags =
	(tag == RPMTAG_HEADERIMMUTABLE ? 0 : HEADERGET_SIGHEADER);
    HeaderIterator hi;

    for (hi = headerInit(h);
	headerNext(hi, he, flags);
	he->p.ptr = _free(he->p.ptr))
    {
	headerPut(nh, he, 0);
    }
    headerFini(hi);

    headerFree(h);
    if (tag == RPMTAG_HEADERIMMUTABLE) {
        headerFree(rpmst->header);
        rpmst->header = headerLink(nh);
    } else {
        headerFree(rpmst->signature);
        rpmst->signature = headerLink(nh);
    }
    headerFree(nh);
#else	/* RPM5 */
    Header hdr;
    HeaderIterator hdr_iter;
    rpmtd copy_td;
    rpmtd td = rpmtdNew();

    if (headerGet(rpmst->header, tag, td, HEADERGET_DEFAULT)) {
        headerFree(rpmst->header);
        rpmst->header = headerNew();
        copy_td = rpmtdNew();

        hdr = headerCopyLoad(td->data);
        hdr_iter = headerInitIterator(hdr);

        while (headerNext(hdr_iter, copy_td)) {
            if (copy_td->data)
                headerPut(rpmst->header, copy_td, HEADERPUT_DEFAULT);
            rpmtdFreeData(copy_td);
        }

        headerFreeIterator(hdr_iter);
        headerFree(hdr);
        rpmtdFreeData(td);
        rpmtdFree(copy_td);
    }

    rpmtdFree(td);
#endif	/* RPM5 */
}

int rpm_read_archive(struct rpm *rpmst, const char *filename,
                     off_t offset, bool decompress, unsigned short *comp_ret,
                     MD5_CTX *seq_md5, MD5_CTX *full_md5)
{
    struct decompstrm *stream = NULL;
    int fdno;
    unsigned char *archive_tmp;
    unsigned char b[BUFFER_SIZE];
    ssize_t nr;
    MD5_CTX *md5;
    int error = DRPM_ERR_OK;

    if ((fdno = open(filename, O_RDONLY)) < 0)
        return DRPM_ERR_IO;

    if (lseek(fdno, offset, SEEK_SET) != offset) {
        error = DRPM_ERR_IO;
        goto cleanup;
    }

    if (decompress) {
        // hack: never updating both MD5s when decompressing
        md5 = (seq_md5 == NULL) ? full_md5 : seq_md5;

        if ((error = decompstrm_init(&stream, fdno, comp_ret, md5, NULL, 0)) != DRPM_ERR_OK ||
            (error = decompstrm_read_until_eof(stream, &rpmst->archive_size, &rpmst->archive)) != DRPM_ERR_OK ||
            (error = decompstrm_get_comp_size(stream, &rpmst->archive_comp_size)) != DRPM_ERR_OK ||
            (error = decompstrm_destroy(&stream)) != DRPM_ERR_OK)
            goto cleanup;
    } else {
        while ((nr = read(fdno, b, sizeof(b))) > 0) {
            if ((archive_tmp = realloc(rpmst->archive,
                 rpmst->archive_size + nr)) == NULL) {
                error = DRPM_ERR_MEMORY;
                goto cleanup;
            }
            if ((seq_md5 != NULL && MD5_Update(seq_md5, b, nr) != 1) ||
                (full_md5 != NULL && MD5_Update(full_md5, b, nr) != 1)) {
                error = DRPM_ERR_OTHER;
                goto cleanup;
            }
            rpmst->archive = archive_tmp;
            memcpy(rpmst->archive + rpmst->archive_size, b, nr);
            rpmst->archive_size += nr;
        }
        if (nr < 0) {
            error = DRPM_ERR_IO;
            goto cleanup;
        }
        rpmst->archive_comp_size = rpmst->archive_size;
    }

cleanup:
    if (stream != NULL)
        decompstrm_destroy(&stream);

    close(fdno);

    return error;
}

/* Reads RPM (or RPM-like file) from file <filename> into <*rpmst>.
 * The archive may be decompressed, read "as is", or not read at all.
 * If read, the compression method used in the archive is stored in
 * <*archive_comp>.
 * Two MD5 checksums may be created. An MD5 digest of the header
 * and archive will be written to <seq_md5_digest>, while
 * <full_md5_digest> shall be made up of the whole file. */
int rpm_read(struct rpm **rpmst, const char *filename,
             int archive_mode, unsigned short *archive_comp,
             unsigned char seq_md5_digest[MD5_DIGEST_LENGTH],
             unsigned char full_md5_digest[MD5_DIGEST_LENGTH])
{
    int error = DRPM_ERR_OK;
    FD_t fd = NULL;
    off_t file_pos;
    bool include_archive;
    bool decomp_archive = false;
    MD5_CTX seq_md5;
    MD5_CTX full_md5;
    unsigned char *sb = NULL;	/* signature buffer */
    size_t nsb;			/* signature buffer length */
    unsigned char *hb = NULL;	/* header buffer */
    size_t nhb;			/* header buffer length */

    if (rpmst == NULL || filename == NULL)
        return DRPM_ERR_PROG;

    switch (archive_mode) {
    case RPM_ARCHIVE_DONT_READ:
        include_archive = false;
        break;
    case RPM_ARCHIVE_READ_UNCOMP:
        include_archive = true;
        decomp_archive = false;
        break;
    case RPM_ARCHIVE_READ_DECOMP:
        include_archive = true;
        decomp_archive = true;
        break;
    default:
        return DRPM_ERR_PROG;
    }

    if ((*rpmst = malloc(sizeof(struct rpm))) == NULL)
        return DRPM_ERR_MEMORY;

    rpm_init(*rpmst);

    // hack: extra '\0' to prevent rpmlib from compressing (see rpmio.c)
    if ((fd = Fopen(filename, "rb\0")) == NULL)
        return DRPM_ERR_IO;

#ifdef	RPM5
#warning FIXME: rpm_read should print msg on failures
    const char * msg;

   {	msg = NULL;
	switch (rpmpkgRead("Lead", fd, &(*rpmst)->lead, &msg)) {
	default:
	    error = Ferror(fd) ? DRPM_ERR_IO : DRPM_ERR_FORMAT;
	    /*@fallthrough@*/
	case RPMRC_OK:
	    break;
	}
	if (msg)
	    free((void *)msg);
	if (error != DRPM_ERR_OK)
	    goto cleanup;
    }
    {	msg = NULL;
	switch (rpmpkgRead("Signature", fd, &(*rpmst)->signature, &msg)) {
	default:
	    error = Ferror(fd) ? DRPM_ERR_IO : DRPM_ERR_FORMAT;
	    /*@fallthrough@*/
	case RPMRC_OK:
	    break;
	}
	if (msg)
	    free((void *)msg);
	if (error != DRPM_ERR_OK)
	    goto cleanup;
    }
    {	msg = NULL;
	switch (rpmpkgRead("Header", fd, &(*rpmst)->header, &msg)) {
	default:
	    error = Ferror(fd) ? DRPM_ERR_IO : DRPM_ERR_FORMAT;
	    /*@fallthrough@*/
	case RPMRC_OK:
	    break;
	}
	if (msg)
	    free((void *)msg);
	if (error != DRPM_ERR_OK)
	    goto cleanup;
    }
#else	/* RPM5 */
    const unsigned char magic_rpm[4] = {0xED, 0xAB, 0xEE, 0xDB};
    if (Fread((*rpmst)->lead, 1, RPMLEAD_SIZE, fd) != RPMLEAD_SIZE ||
        memcmp((*rpmst)->lead, magic_rpm, 4) != 0 ||
        ((*rpmst)->signature = headerRead(fd, HEADER_MAGIC_YES)) == NULL ||
        (file_pos = Ftell(fd)) < 0 ||
        Fseek(fd, RPMSIG_PADDING(file_pos), SEEK_CUR) < 0 ||
        ((*rpmst)->header = headerRead(fd, HEADER_MAGIC_YES)) == NULL) {
        error = Ferror(fd) ? DRPM_ERR_IO : DRPM_ERR_FORMAT;
        goto cleanup;
    }
#endif	/* RPM5 */

    if (seq_md5_digest != NULL) {
        if ((error = rpm_export_header(*rpmst, &hb, &nhb)) != DRPM_ERR_OK)
            goto cleanup;
        if (MD5_Init(&seq_md5) != 1 ||
            MD5_Update(&seq_md5, hb, nhb) != 1) {
            error = DRPM_ERR_OTHER;
            goto cleanup;
        }
    }

    if (full_md5_digest != NULL) {
        if ((error = rpm_export_signature(*rpmst, &sb, &nsb)) != DRPM_ERR_OK ||
            (hb == NULL && (error = rpm_export_header(*rpmst, &hb, &nhb)) != DRPM_ERR_OK))
            goto cleanup;
        if (MD5_Init(&full_md5) != 1 ||
            MD5_Update(&full_md5, (*rpmst)->lead, RPMLEAD_SIZE) != 1 ||
            MD5_Update(&full_md5, sb, nsb) != 1 ||
            MD5_Update(&full_md5, hb, nhb) != 1) {
            error = DRPM_ERR_OTHER;
            goto cleanup;
        }
    }

    if (include_archive) {
        if ((file_pos = Ftell(fd)) < 0) {
            error = DRPM_ERR_IO;
            goto cleanup;
        }
        if ((error = rpm_read_archive(*rpmst, filename, file_pos,
                                      decomp_archive, archive_comp,
                                      (seq_md5_digest != NULL) ? &seq_md5 : NULL,
                                      (full_md5_digest != NULL) ? &full_md5 : NULL)) != DRPM_ERR_OK)
            goto cleanup;
    }

    if ((seq_md5_digest != NULL && MD5_Final(seq_md5_digest, &seq_md5) != 1) ||
        (full_md5_digest != NULL && MD5_Final(full_md5_digest, &full_md5) != 1)) {
        error = DRPM_ERR_OTHER;
        goto cleanup;
    }

cleanup:
    if (error != DRPM_ERR_OK)
	rpm_free(*rpmst);
    free(sb);
    free(hb);
    Fclose(fd);

    return error;
}

/* Frees RPM data. */
int rpm_destroy(struct rpm **rpmst)
{
    if (rpmst == NULL || *rpmst == NULL)
        return DRPM_ERR_PROG;

    rpm_free(*rpmst);
    free(*rpmst);
    *rpmst = NULL;

    return DRPM_ERR_OK;
}

/* Reads <count> bytes to <buffer> from the current offset in the archive. */
int rpm_archive_read_chunk(struct rpm *rpmst, void *buffer, size_t count)
{
    if (rpmst == NULL)
        return DRPM_ERR_PROG;

    if (rpmst->archive_offset + count > rpmst->archive_size)
        return DRPM_ERR_FORMAT;

    if (buffer != NULL)
        memcpy(buffer, rpmst->archive + rpmst->archive_offset, count);

    rpmst->archive_offset += count;

    return DRPM_ERR_OK;
}

/* Positions the archive offset at the beginning of the archive. */
int rpm_archive_rewind(struct rpm *rpmst)
{
    if (rpmst == NULL)
        return DRPM_ERR_PROG;

    rpmst->archive_offset = 0;

    return DRPM_ERR_OK;
}

/* Returns the on-disk size of the RPM file. This will be without
 * the archive if it wasn't read. */
uint32_t rpm_size_full(struct rpm *rpmst)
{
    if (rpmst == NULL)
        return 0;

#ifdef	RPM5
    size_t nsb = headerSizeof(rpmst->signature);
    size_t nhb = headerSizeof(rpmst->header);

    return RPMLEAD_SIZE + nsb + RPMSIG_PADDING(nsb) + nhb +
           rpmst->archive_comp_size;
#else	/* RPM5 */
    unsigned sig_size = headerSizeof(rpmst->signature, HEADER_MAGIC_YES);

    return RPMLEAD_SIZE + sig_size + RPMSIG_PADDING(sig_size) +
           headerSizeof(rpmst->header, HEADER_MAGIC_YES) +
           rpmst->archive_comp_size;
#endif	/* RPM5 */
}

/* Returns the size of the RPM header. */
uint32_t rpm_size_header(struct rpm *rpmst)
{
    if (rpmst == NULL)
        return 0;

#ifdef	RPM5
    return headerSizeof(rpmst->header);
#else	/* RPM5 */
    return headerSizeof(rpmst->header, HEADER_MAGIC_YES);
#endif	/* RPM5 */
}

/* Fetches a concatenation of the on-disk RPM lead and signature. */
int rpm_fetch_lead_and_signature(struct rpm *rpmst,
                                 unsigned char **bp, uint32_t *nbp)
{
    unsigned char *sb = NULL;	/* signature buffer */
    size_t nsb = 0;		/* signtaure buffer length */
    size_t nb;			/* lead+signature length */
    int error = DRPM_ERR_OK;

    if (rpmst == NULL || bp == NULL || nbp == NULL)
        return DRPM_ERR_PROG;

    *bp = NULL;
    *nbp = 0;

    if ((error = rpm_export_signature(rpmst, &sb, &nsb)) != DRPM_ERR_OK)
        goto cleanup;

    nb = RPMLEAD_SIZE + nsb;

    if ((*bp = malloc(nb)) == NULL) {
        error = DRPM_ERR_MEMORY;
        goto cleanup;
    }

    memcpy(*bp, rpmst->lead, RPMLEAD_SIZE);
    memcpy(*bp + RPMLEAD_SIZE, sb, nsb);

    *nbp = nb;

cleanup:
    if (sb)
	free(sb);

    return error;
}

/* Fetches the on-disk RPM header. */
int rpm_fetch_header(struct rpm *rpmst, unsigned char **bp, uint32_t *nbp)
{
    int error;
    size_t nb = 0;

    if ((error = rpm_export_header(rpmst, bp, &nb)) != DRPM_ERR_OK)
        return error;

    *nbp = nb;

    return DRPM_ERR_OK;
}

/* Fetches the archive (in whatever format it was read). */
int rpm_fetch_archive(struct rpm *rpmst, unsigned char **bp, size_t *nbp)
{
    if (rpmst == NULL || bp == NULL || nbp == NULL)
        return DRPM_ERR_PROG;

    if ((*bp = malloc(rpmst->archive_size)) == NULL)
        return DRPM_ERR_MEMORY;

    memcpy(*bp, rpmst->archive, rpmst->archive_size);
    *nbp = rpmst->archive_size;

    return DRPM_ERR_OK;
}

/* Writes the RPM to <filename>. Will not write the archive unless
 * <include_archive> is true. May also write an MD5 digest of written
 * data to <digest>. If <full_md5> is false, then this will not include
 * the lead and signature. */
int rpm_write(struct rpm *rpmst, const char *filename, bool include_archive, unsigned char digest[MD5_DIGEST_LENGTH], bool full_md5)
{
    int error = DRPM_ERR_OK;
    FD_t fd;
    unsigned char *sb = NULL;	/* signature buffer */
    size_t nsb;			/* signature buffer length */
    unsigned char *hb = NULL;	/* header buffer */
    size_t nhb;			/* header buffer length */
    MD5_CTX md5;

    if (rpmst == NULL)
        return DRPM_ERR_PROG;

    // hack: extra '\0' to prevent rpmlib from compressing (see rpmio.c)
    if ((fd = Fopen(filename, "wb\0")) == NULL)
        return DRPM_ERR_IO;

    if ((error = rpm_export_signature(rpmst, &sb, &nsb)) != DRPM_ERR_OK ||
        (error = rpm_export_header(rpmst, &hb, &nhb)) != DRPM_ERR_OK)
        goto cleanup;

    if (Fwrite(rpmst->lead, 1, RPMLEAD_SIZE, fd) != RPMLEAD_SIZE ||
        (ssize_t)Fwrite(sb, 1, nsb, fd) != (ssize_t)nsb ||
        (ssize_t)Fwrite(hb, 1, nhb, fd) != (ssize_t)nhb) {
        error = DRPM_ERR_IO;
        goto cleanup;
    }

    if (digest != NULL) {
        if (MD5_Init(&md5) != 1 ||
            (full_md5 &&
             (MD5_Update(&md5, rpmst->lead, RPMLEAD_SIZE) != 1 ||
              MD5_Update(&md5, sb, nsb) != 1)) ||
            MD5_Update(&md5, hb, nhb) != 1) {
            error = DRPM_ERR_OTHER;
            goto cleanup;
        }
    }

    if (include_archive) {
        if ((ssize_t)Fwrite(rpmst->archive, 1, rpmst->archive_size, fd)
            != (ssize_t)rpmst->archive_size) {
            error = DRPM_ERR_IO;
            goto cleanup;
        }
        if (digest != NULL && MD5_Update(&md5, rpmst->archive, rpmst->archive_size) != 1) {
            error = DRPM_ERR_OTHER;
            goto cleanup;
        }
    }

    if (digest != NULL && MD5_Final(digest, &md5) != 1) {
        error = DRPM_ERR_OTHER;
        goto cleanup;
    }

cleanup:
    Fclose(fd);
    if (sb)
        free(sb);
    if (hb)
        free(hb);

    return error;
}

/* Replaces the lead and signature with data import from <leadsig>. */
int rpm_replace_lead_and_signature(struct rpm *rpmst, unsigned char *leadsig, size_t leadsig_len)
{
    int error = DRPM_ERR_OK;
    const size_t skip = RPMLEAD_SIZE + sizeof(rpm_header_magic);

    if (rpmst == NULL || leadsig == NULL || leadsig_len < RPM_LEADSIG_MIN_LEN)
        return DRPM_ERR_PROG;

    if (memcmp(leadsig + RPMLEAD_SIZE, rpm_header_magic, 4) != 0)
        return DRPM_ERR_FORMAT;

    memcpy(rpmst->lead, leadsig, RPMLEAD_SIZE);

    headerFree(rpmst->signature);
    rpmst->signature = NULL;

    rpmst->signature = headerImport(leadsig + skip, 0, HEADERIMPORT_COPY);
    if (rpmst->signature == NULL)
        return DRPM_ERR_FORMAT;

    return error;
}

/* Checks if this is a source RPM. */
bool rpm_is_sourcerpm(struct rpm *rpmst)
{
    return (headerGetString(rpmst->header, RPMTAG_SOURCERPM) == NULL);
}

/* Fetches the NEVR string from the header. */
int rpm_get_nevr(struct rpm *rpmst, char **nevr)
{
    int error = DRPM_ERR_OK;
    if (rpmst == NULL || nevr == NULL)
        return DRPM_ERR_PROG;

    if ((*nevr = headerGetAsString(rpmst->header, RPMTAG_NEVR)) == NULL)
        return DRPM_ERR_MEMORY;

    return error;
}

/* Determines the payload compression from information in the header. */
int rpm_get_comp(struct rpm *rpmst, unsigned short *comp)
{
    int error = DRPM_ERR_OK;
    const char *payload_comp;

    if (rpmst == NULL || comp == NULL)
        return DRPM_ERR_PROG;

    if ((payload_comp = headerGetString(rpmst->header, RPMTAG_PAYLOADCOMPRESSOR)) == NULL)
        return DRPM_ERR_FORMAT;

    if (strcmp(payload_comp, "gzip") == 0) {
        *comp = DRPM_COMP_GZIP;
    } else if (strcmp(payload_comp, "bzip2") == 0) {
        *comp = DRPM_COMP_BZIP2;
    } else if (strcmp(payload_comp, "lzip") == 0) {
        *comp = DRPM_COMP_LZIP;
    } else if (strcmp(payload_comp, "lzma") == 0) {
        *comp = DRPM_COMP_LZMA;
    } else if (strcmp(payload_comp, "xz") == 0) {
        *comp = DRPM_COMP_XZ;
    } else {
        return DRPM_ERR_FORMAT;
    }

    return error;
}

/* Determines the compression level from the header. */
int rpm_get_comp_level(struct rpm *rpmst, unsigned short *level)
{
    int error = DRPM_ERR_OK;
    const char *payload_flags;

    if (rpmst == NULL || level == NULL)
        return DRPM_ERR_PROG;

    if ((payload_flags = headerGetString(rpmst->header, RPMTAG_PAYLOADFLAGS)) == NULL)
        return DRPM_ERR_FORMAT;

    if (strlen(payload_flags) != 1 ||
        payload_flags[0] < '1' || payload_flags[0] > '9')
        return DRPM_ERR_FORMAT;

    *level = payload_flags[0] - '0';

    return error;
}

/* Determines the digest algorithm used for file checksums in the header. */
int rpm_get_digest_algo(struct rpm *rpmst, unsigned short *digestalgo)
{
    int error = DRPM_ERR_OK;

    if (rpmst == NULL || digestalgo == NULL)
        return DRPM_ERR_PROG;

#ifdef	RPM5
#warning rpm_get_digest_algo() set digests other than MD5/SHA256.
    uint32_t algo = headerGetNumber(rpmst->header, RPMTAG_FILEDIGESTALGO);
    if (algo == 0)
	algo = RFC4880_HASH_ALGO_MD5;
    switch (algo) {
    case RFC4880_HASH_ALGO_MD5:
	*digestalgo = DIGESTALGO_MD5;
	break;
    case RFC4880_HASH_ALGO_SHA256:
	*digestalgo = DIGESTALGO_SHA256;
	break;
    default:
	error = DRPM_ERR_FORMAT;
	break;
    }
#else	/* RPM5 */
    rpmtd digest_algo_array;
    uint32_t *digest_algo;

    digest_algo_array = rpmtdNew();

    if (headerGet(rpmst->header, RPMTAG_FILEDIGESTALGO, digest_algo_array,
                  HEADERGET_EXT | HEADERGET_MINMEM) != 1) {
        *digestalgo = DIGESTALGO_MD5;
    } else {
        if ((digest_algo = rpmtdNextUint32(digest_algo_array)) == NULL) {
            error = DRPM_ERR_FORMAT;
            goto cleanup;
        }

        switch (*digest_algo) {
        case RFC4880_HASH_ALGO_MD5:
            *digestalgo = DIGESTALGO_MD5;
            break;
        case RFC4880_HASH_ALGO_SHA256:
            *digestalgo = DIGESTALGO_SHA256;
            break;
        default:
            error = DRPM_ERR_FORMAT;
            goto cleanup;
        }
    }

cleanup:
    rpmtdFreeData(digest_algo_array);
    rpmtdFree(digest_algo_array);
#endif	/* RPM5 */

    return error;
}

/* Determines the payload format from the header. */
int rpm_get_payload_format(struct rpm *rpmst, unsigned short *payfmt)
{
    int error = DRPM_ERR_OK;
    const char *payload_format;

    if (rpmst == NULL || payfmt == NULL)
        return DRPM_ERR_PROG;

    if ((payload_format = headerGetString(rpmst->header, RPMTAG_PAYLOADFORMAT)) == NULL)
        return DRPM_ERR_MEMORY;

    if (strcmp(payload_format, "drpm") == 0) {
        *payfmt = RPM_PAYLOAD_FORMAT_DRPM;
    } else if (strcmp(payload_format, "cpio") == 0) {
        *payfmt = RPM_PAYLOAD_FORMAT_CPIO;
    } else if (strcmp(payload_format, "xar") == 0) {
        *payfmt = RPM_PAYLOAD_FORMAT_XAR;
    } else {
        return DRPM_ERR_FORMAT;
    }

    return error;
}

/* Replaces the payload format information in the header. */
int rpm_patch_payload_format(struct rpm *rpmst, const char *new_payfmt)
{
    int error = DRPM_ERR_OK;

    if (rpmst == NULL || new_payfmt == NULL)
        return DRPM_ERR_PROG;

    rpm_header_unload_region(rpmst, RPMTAG_HEADERIMMUTABLE);

#ifdef	RPM5
    Header h = rpmst->header;
    HE_t he = (HE_t) memset(alloca(sizeof(*he)), 0, sizeof(*he));

    he->tag = RPMTAG_PAYLOADFORMAT;
    if (headerDel(h, he, 0) != 1)
        return DRPM_ERR_FORMAT;

    he->tag = RPMTAG_PAYLOADFORMAT;
    he->t = RPM_STRING_TYPE;
    he->p.str = new_payfmt;
    he->c = 1;
    if (headerPut(h, he, 0) != 1)
        return DRPM_ERR_FORMAT;
#else	/* RPM5 */
    if (headerDel(rpmst->header, RPMTAG_PAYLOADFORMAT) != 0)
        return DRPM_ERR_FORMAT;

    if (headerPutString(rpmst->header, RPMTAG_PAYLOADFORMAT, new_payfmt) != 1)
        return DRPM_ERR_FORMAT;
#endif	/* RPM5 */

    rpmst->header = headerReload(rpmst->header, RPMTAG_HEADERIMMUTABLE);

    return error;
}

/* Fetches a list of file information from the header. */
int rpm_get_file_info(struct rpm *rpmst, struct file_info **files_ret,
                      size_t *count_ret, bool *colors_ret)
{
    int error = DRPM_ERR_OK;
    struct file_info *files = NULL;
    size_t count = 0;
    bool colors;

    if (rpmst == NULL || files_ret == NULL || count_ret == NULL)
        return DRPM_ERR_PROG;

#ifdef	RPM5
    HE_t he = (HE_t) memset(alloca(sizeof(*he)), 0, sizeof(*he));
    Header h = rpmst->header;
    rpmfi fi;
    int i;

    fi = rpmfiNew(NULL, h, RPMTAG_BASENAMES, 0);
    if (fi == NULL) {
        error = DRPM_ERR_FORMAT;
        goto cleanup;
    }
    count = rpmfiFC(fi);
    colors = (colors_ret != NULL) ? true : false;

    /* XXX add 1 to ensure something is returned. */
    if ((files = calloc(count+1, sizeof(*files))) == NULL) {
        error = DRPM_ERR_MEMORY;
        goto cleanup;
    }

    if (count > 0) {
	/* XXX rpmfi has binary, not hex, digests. */
	he->tag = RPMTAG_FILEDIGESTS;
	if (headerGet(h, he, 0) != 1 || he->c != count) {
	    error = DRPM_ERR_FORMAT;
	    goto cleanup;
	}
    }
    
    while ((i = rpmfiNext(fi)) >= 0) {
	files[i].name = strdup(rpmfiFN(fi));
	files[i].flags = rpmfiFFlags(fi);
	files[i].md5 = strdup(he->p.argv[i]);
	files[i].rdev = rpmfiFRdev(fi);
	files[i].size = rpmfiFSize(fi);
	files[i].mode = rpmfiFMode(fi);
	files[i].verify = rpmfiVFlags(fi);
	files[i].linkto = strdup(rpmfiFLink(fi));
	if (colors)
	    files[i].color = rpmfiColor(fi);
    }

cleanup:
    if (error == DRPM_ERR_OK) {
	*files_ret = files;
	*count_ret = count;
	if (colors_ret != NULL)
	    *colors_ret = colors;
    } else if (files != NULL) {
	for (i = 0; i < (int)count; i++) {
	    free(files[i].name);
	    free(files[i].md5);
	    free(files[i].linkto);
	}
	free(files);
    }
    if (he->p.ptr)
	free(he->p.ptr);
    fi = rpmfiFree(fi);
#else	/* RPM5 */
    const struct file_info file_info_init = {0};
    rpmtd filenames;
    rpmtd fileflags;
    rpmtd filemd5s;
    rpmtd filerdevs;
    rpmtd filesizes;
    rpmtd filemodes;
    rpmtd fileverify;
    rpmtd filelinktos;
    rpmtd filecolors;
    const char *name;
    uint32_t *flags;
    const char *md5;
    uint16_t *rdev;
    uint32_t *size;
    uint16_t *mode;
    uint32_t *verify;
    const char *linkto;
    uint32_t *color = NULL;

    filenames = rpmtdNew();
    fileflags = rpmtdNew();
    filemd5s = rpmtdNew();
    filerdevs = rpmtdNew();
    filesizes = rpmtdNew();
    filemodes = rpmtdNew();
    fileverify = rpmtdNew();
    filelinktos = rpmtdNew();
    filecolors = rpmtdNew();

    if (headerGet(rpmst->header, RPMTAG_FILENAMES, filenames, HEADERGET_EXT) != 1 ||
        headerGet(rpmst->header, RPMTAG_FILEFLAGS, fileflags, HEADERGET_MINMEM) != 1 ||
        headerGet(rpmst->header, RPMTAG_FILEMD5S, filemd5s, HEADERGET_MINMEM) != 1 ||
        headerGet(rpmst->header, RPMTAG_FILERDEVS, filerdevs, HEADERGET_MINMEM) != 1 ||
        headerGet(rpmst->header, RPMTAG_FILESIZES, filesizes, HEADERGET_MINMEM) != 1 ||
        headerGet(rpmst->header, RPMTAG_FILEMODES, filemodes, HEADERGET_MINMEM) != 1 ||
        headerGet(rpmst->header, RPMTAG_FILEVERIFYFLAGS, fileverify, HEADERGET_MINMEM) != 1 ||
        headerGet(rpmst->header, RPMTAG_FILELINKTOS, filelinktos, HEADERGET_MINMEM) != 1) {
        error = DRPM_ERR_FORMAT;
        goto cleanup;
    }

    colors = (colors_ret == NULL) ? false :
             (headerGet(rpmst->header, RPMTAG_FILECOLORS, filecolors, HEADERGET_MINMEM) == 1);

    count = rpmtdCount(filenames);
    if (count != rpmtdCount(fileflags) ||
        count != rpmtdCount(filemd5s) ||
        count != rpmtdCount(filerdevs) ||
        count != rpmtdCount(filesizes) ||
        count != rpmtdCount(filemodes) ||
        count != rpmtdCount(fileverify) ||
        count != rpmtdCount(filelinktos) ||
        (colors && count != rpmtdCount(filecolors))) {
        error = DRPM_ERR_FORMAT;
        goto cleanup;
    }

    if ((files = malloc(count * sizeof(struct file_info))) == NULL) {
        error = DRPM_ERR_MEMORY;
        goto cleanup;
    }

    for (size_t i = 0; i < count; i++)
        files[i] = file_info_init;

    for (size_t i = 0; i < count; i++) {
        if ((name = rpmtdNextString(filenames)) == NULL ||
            (flags = rpmtdNextUint32(fileflags)) == NULL ||
            (md5 = rpmtdNextString(filemd5s)) == NULL ||
            (size = rpmtdNextUint32(filesizes)) == NULL ||
            (verify = rpmtdNextUint32(fileverify)) == NULL ||
            (linkto = rpmtdNextString(filelinktos)) == NULL ||
            (colors && (color = rpmtdNextUint32(filecolors)) == NULL) ||
            rpmtdNext(filerdevs) < 0 ||
            rpmtdNext(filemodes) < 0 ||
            (rdev = rpmtdGetUint16(filerdevs)) == NULL ||
            (mode = rpmtdGetUint16(filemodes)) == NULL) {
            error = DRPM_ERR_FORMAT;
            goto cleanup_files;
        }

        if ((files[i].name = malloc(strlen(name) + 1)) == NULL ||
            (files[i].md5 = malloc(strlen(md5) + 1)) == NULL ||
            (files[i].linkto = malloc(strlen(linkto) + 1)) == NULL) {
            error = DRPM_ERR_MEMORY;
            goto cleanup_files;
        }

        strcpy(files[i].name, name);
        files[i].flags = *flags;
        strcpy(files[i].md5, md5);
        files[i].rdev = *rdev;
        files[i].size = *size;
        files[i].mode = *mode;
        files[i].verify = *verify;
        strcpy(files[i].linkto, linkto);
        if (colors)
            files[i].color = *color;
    }

    *files_ret = files;
    *count_ret = count;
    if (colors_ret != NULL)
        *colors_ret = colors;

    goto cleanup;

cleanup_files:
    for (size_t i = 0; i < count; i++) {
        free(files[i].name);
        free(files[i].md5);
        free(files[i].linkto);
    }

    free(files);

cleanup:
    rpmtdFreeData(filenames);
    rpmtdFreeData(fileflags);
    rpmtdFreeData(filemd5s);
    rpmtdFreeData(filerdevs);
    rpmtdFreeData(filesizes);
    rpmtdFreeData(filemodes);
    rpmtdFreeData(fileverify);
    rpmtdFreeData(filelinktos);
    rpmtdFreeData(filecolors);

    rpmtdFree(filenames);
    rpmtdFree(fileflags);
    rpmtdFree(filemd5s);
    rpmtdFree(filerdevs);
    rpmtdFree(filesizes);
    rpmtdFree(filemodes);
    rpmtdFree(fileverify);
    rpmtdFree(filelinktos);
    rpmtdFree(filecolors);
#endif	/* RPM5 */

    return error;
}

/* Calculates the offset of the payload format string in the header. */
int rpm_find_payload_format_offset(struct rpm *rpmst, uint32_t *offset)
{
    unsigned char *header;
    size_t header_size;
    uint32_t index_count;
    int error;

    if (rpmst == NULL || offset == NULL)
        return DRPM_ERR_PROG;

    if ((error = rpm_export_header(rpmst, &header, &header_size)) != DRPM_ERR_OK)
        return error;

    error = DRPM_ERR_FORMAT;

    index_count = parse_be32(header + 8);

    for (uint32_t i = 0, off = 16; i < index_count && off+16 <= header_size;
         i++, off += 16) {
        if (parse_be32(header + off) == RPMTAG_PAYLOADFORMAT) {
            *offset = parse_be32(header + off + 8);
            error = DRPM_ERR_OK;
            goto cleanup;
        }
    }

cleanup:
    free(header);

    return error;
}

/* Empties the signature. */
int rpm_signature_empty(struct rpm *rpmst)
{
    if (rpmst == NULL)
        return DRPM_ERR_PROG;

    headerFree(rpmst->signature);
    rpmst->signature = headerNew();

    return DRPM_ERR_OK;
}

/* Sets size tag in the signature.
 * Should be equal to the size all data following the signature. */
int rpm_signature_set_size(struct rpm *rpmst, uint32_t size)
{
    int error = DRPM_ERR_OK;

    if (rpmst == NULL)
        return DRPM_ERR_PROG;

#ifdef	RPM5
    Header sigh = rpmst->signature;
    HE_t he = (HE_t) memset(alloca(sizeof(*he)), 0, sizeof(*he));

    he->tag = RPMSIGTAG_SIZE;
    he->t = RPM_UINT32_TYPE;
    he->p.ui32p = &size;
    he->c = 1;
    if (headerPut(sigh, he, 0) != 1)
        return DRPM_ERR_FORMAT;
#else	/* RPM5 */
    rpmtd tag_data = rpmtdNew();

    tag_data->tag = RPMSIGTAG_SIZE;
    tag_data->type = RPM_INT32_TYPE;
    tag_data->data = &size;
    tag_data->count = 1;

    headerPut(rpmst->signature, tag_data, HEADERPUT_DEFAULT);

    rpmtdFree(tag_data);
#endif	/* RPM5 */

    return error;
}

/* Sets MD5 tag in the signature.
 * Should be equal to the MD5 sum of all data following the signature. */
int rpm_signature_set_md5(struct rpm *rpmst, unsigned char md5[MD5_DIGEST_LENGTH])
{
    int error = DRPM_ERR_OK;

    if (rpmst == NULL || md5 == NULL)
        return DRPM_ERR_PROG;

#ifdef	RPM5
    Header sigh = rpmst->signature;
    HE_t he = (HE_t) memset(alloca(sizeof(*he)), 0, sizeof(*he));

    he->tag = RPMSIGTAG_SIZE;
    he->t = RPM_BIN_TYPE;
    he->p.ptr = md5;
    he->c = MD5_DIGEST_LENGTH;
    if (headerPut(sigh, he, 0) != 1)
        return DRPM_ERR_FORMAT;
#else	/* RPM5 */
    rpmtd tag_data = rpmtdNew();

    tag_data->tag = RPMSIGTAG_MD5;
    tag_data->type = RPM_BIN_TYPE;
    tag_data->data = md5;
    tag_data->count = MD5_DIGEST_LENGTH;

    headerPut(rpmst->signature, tag_data, HEADERPUT_DEFAULT);

    rpmtdFree(tag_data);
#endif	/* RPM5 */

    return error;
}

/* Reloads the signature to accomodate for changes. */
int rpm_signature_reload(struct rpm *rpmst)
{
    rpmst->signature = headerReload(rpmst->signature, RPMTAG_HEADERSIGNATURES);

    return DRPM_ERR_OK;
}

/* Fetches the MD5 sum from the signature. */
int rpm_signature_get_md5(struct rpm *rpmst, unsigned char md5[MD5_DIGEST_LENGTH], bool *has_md5)
{
    int error = DRPM_ERR_OK;

    if (rpmst == NULL || md5 == NULL || has_md5 == NULL)
        return DRPM_ERR_PROG;

#ifdef	RPM5
    Header sigh = rpmst->signature;
    HE_t he = (HE_t) memset(alloca(sizeof(*he)), 0, sizeof(*he));

    he->tag = RPMSIGTAG_MD5;
    *has_md5 = (headerGet(sigh, he, HEADERGET_SIGHEADER) == 1);
    if (!*has_md5)
        return DRPM_ERR_FORMAT;
    if (he->c == MD5_DIGEST_LENGTH)
	memcpy(md5, he->p.ptr, he->c);
    else
	error = DRPM_ERR_FORMAT;
    rpmheFree(he);
#else	/* RPM5 */
    rpmtd tag_data = rpmtdNew();

    if ((*has_md5 = (headerGet(rpmst->signature, RPMSIGTAG_MD5, tag_data, HEADERGET_MINMEM) == 1))) {
        if (tag_data->count != MD5_DIGEST_LENGTH) {
            error = DRPM_ERR_FORMAT;
            goto cleanup;
        }

        memcpy(md5, tag_data->data, MD5_DIGEST_LENGTH);
    }

cleanup:
    rpmtdFree(tag_data);
#endif	/* RPM5 */

    return error;
}

/* Reads only the header of an installed RPM from the database.
 * The RPM is identified by its <nevr> string. */
int rpm_read_header(struct rpm **rpmst, const char *nevr, const char *arch)
{
    int error = DRPM_ERR_OK;
    rpmts trans = NULL;
    rpmdbMatchIterator iter = NULL;
    char *name;
    char *epoch = NULL;
    char *version;
    char *release;
    char *str = NULL;
    unsigned char *header = NULL;
    size_t header_size;

    if (rpmst == NULL || nevr == NULL)
        return DRPM_ERR_PROG;

    if ((*rpmst = malloc(sizeof(struct rpm))) == NULL ||
        (str = malloc(strlen(nevr) + 1)) == NULL) {
        error = DRPM_ERR_MEMORY;
        goto cleanup_fail;
    }

    rpm_init(*rpmst);

    strcpy(str, nevr);
    release = strrchr(str, '-');
    if (release == NULL || release == str) {
        error = DRPM_ERR_FORMAT;
        goto cleanup_fail;
    }
    *release++ = '\0';
    version = strrchr(str, ':');
    if (version == str) {
        error = DRPM_ERR_FORMAT;
        goto cleanup_fail;
    }
    if (version == NULL) {
        version = strrchr(str, '-');
        if (version == NULL || version == str) {
            error = DRPM_ERR_FORMAT;
            goto cleanup_fail;
        }
        *version++ = '\0';
    } else {
        *version++ = '\0';
        epoch = strrchr(str, '-');
        if (epoch == NULL || epoch == str) {
            error = DRPM_ERR_FORMAT;
            goto cleanup_fail;
        }
        *epoch++ = '\0';
    }
    name = str;

    rpmReadConfigFiles(NULL, NULL);

    trans = rpmtsCreate();

    iter = rpmtsInitIterator(trans, RPMTAG_NAME, name, 0);
    rpmdbSetIteratorRE(iter, RPMTAG_EPOCH, RPMMIRE_STRCMP, epoch);
    rpmdbSetIteratorRE(iter, RPMTAG_VERSION, RPMMIRE_STRCMP, version);
    rpmdbSetIteratorRE(iter, RPMTAG_RELEASE, RPMMIRE_STRCMP, release);
    if (arch)
        rpmdbSetIteratorRE(iter, RPMTAG_ARCH, RPMMIRE_STRCMP, arch);

    if (((*rpmst)->header = rpmdbNextIterator(iter)) == NULL) {
        error = DRPM_ERR_NOINSTALL;
        goto cleanup_fail;
    }

    if ((error = rpm_export_header(*rpmst, &header, &header_size)) != DRPM_ERR_OK)
        goto cleanup_fail;

    (*rpmst)->header = headerImport(header + sizeof(rpm_header_magic), 0, HEADERIMPORT_COPY);
    if ((*rpmst)->header == NULL) {
        error = DRPM_ERR_OTHER;
        goto cleanup_fail;
    }

    goto cleanup;

cleanup_fail:
    if (*rpmst != NULL) {
        rpm_free(*rpmst);
        free(*rpmst);
        *rpmst = NULL;
    }

cleanup:
    rpmdbFreeIterator(iter);
    rpmtsFree(trans);
    free(str);

    return error;
}
