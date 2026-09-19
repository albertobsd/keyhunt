/*
 * getopt.c - self-contained POSIX getopt() for Windows / MSVC.
 *
 * This is only compiled on native Windows builds (see CMakeLists.txt /
 * keyhunt.vcxproj); on POSIX platforms the C library already provides
 * getopt() through <unistd.h>.
 *
 * Behaviour matches the classic short-option getopt():
 *   - options are single characters listed in optstring;
 *   - a character followed by ':' in optstring takes a required argument,
 *     given either attached ("-fVALUE") or as the next argv element
 *     ("-f VALUE");
 *   - "--" terminates option scanning;
 *   - on an unknown option or a missing required argument it returns '?'
 *     (or ':' when optstring begins with ':') and sets optopt.
 *
 * Public domain. No warranty.
 */
#include "getopt.h"

#include <stdio.h>
#include <string.h>

char *optarg = NULL;
int   optind = 1;
int   opterr = 1;
int   optopt = 0;

int getopt(int argc, char *const argv[], const char *optstring)
{
    static int optpos = 1;           /* position inside a bundled argv[optind] */
    const char *arg;
    const char *opt;
    int c;

    /* Allow the caller to restart scanning by resetting optind to 0 or 1. */
    if (optind == 0) {
        optind = 1;
        optpos = 1;
    }

    optarg = NULL;

    arg = (optind < argc) ? argv[optind] : NULL;

    if (arg == NULL || arg[0] != '-' || arg[1] == '\0') {
        /* Not an option (or a lone "-"): stop. */
        return -1;
    }

    if (arg[1] == '-' && arg[2] == '\0') {
        /* "--" explicitly ends option processing. */
        optind++;
        return -1;
    }

    c = (unsigned char)arg[optpos];
    opt = (c == ':') ? NULL : strchr(optstring, c);

    if (opt == NULL) {
        /* Unknown option character. */
        optopt = c;
        if (opterr && optstring[0] != ':') {
            fprintf(stderr, "%s: invalid option -- '%c'\n", argv[0], c);
        }
        if (arg[++optpos] == '\0') {
            optind++;
            optpos = 1;
        }
        return '?';
    }

    if (opt[1] == ':') {
        /* Option requires an argument. */
        if (arg[optpos + 1] != '\0') {
            /* Attached argument: -fVALUE */
            optarg = (char *)(arg + optpos + 1);
            optind++;
            optpos = 1;
            return c;
        } else if (optind + 1 < argc) {
            /* Separate argument: -f VALUE */
            optarg = argv[optind + 1];
            optind += 2;
            optpos = 1;
            return c;
        } else {
            /* Missing required argument. */
            optopt = c;
            optind++;
            optpos = 1;
            if (optstring[0] == ':') {
                return ':';
            }
            if (opterr) {
                fprintf(stderr,
                        "%s: option requires an argument -- '%c'\n",
                        argv[0], c);
            }
            return '?';
        }
    }

    /* Plain flag with no argument. Advance within the bundle. */
    if (arg[++optpos] == '\0') {
        optind++;
        optpos = 1;
    }
    return c;
}
