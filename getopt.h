/*
 * getopt.h - minimal POSIX getopt() declaration for Windows / MSVC.
 *
 * On Linux, macOS and Cygwin the system <unistd.h> already provides getopt(),
 * so keyhunt only includes this header on native Windows builds. The matching
 * implementation lives in getopt.c and is a self-contained, public-domain
 * getopt() supporting the classic short-option syntax used by keyhunt
 * (single letters, ':' marking a required argument).
 *
 * Public domain. No warranty.
 */
#ifndef KEYHUNT_GETOPT_H
#define KEYHUNT_GETOPT_H

#ifdef __cplusplus
extern "C" {
#endif

extern char *optarg;   /* argument of the current option (or NULL)          */
extern int   optind;   /* index of the next element of argv to process      */
extern int   opterr;   /* set to 0 to suppress error messages               */
extern int   optopt;   /* the option character that caused an error         */

int getopt(int argc, char *const argv[], const char *optstring);

#ifdef __cplusplus
}
#endif

#endif /* KEYHUNT_GETOPT_H */
