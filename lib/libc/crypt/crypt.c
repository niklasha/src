/*	$OpenBSD: crypt.c,v 1.31 2015/09/12 14:56:50 guenther Exp $	*/

#include <errno.h>
#include <pwd.h>
#include <unistd.h>

char *
crypt(const char *key, const char *setting)
{
	extern char *md5crypt(const char *, const char *);
	if (setting[0] == '$') {
		switch (setting[1]) {
		case '1':
			return md5crypt(key, setting);
		case '2':
			return bcrypt(key, setting);
		default:
			errno = EINVAL;
			return (NULL);
		}
	}
	errno = EINVAL;
	return (NULL);
}
DEF_WEAK(crypt);
