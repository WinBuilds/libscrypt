#define _CRT_RAND_S  
#include <stdlib.h>

#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <fcntl.h>

/* Disable on Windows, there is no /dev/urandom.
   Link-time error is better than runtime error. */
#ifdef _WIN32

int libscrypt_salt_gen(uint8_t *salt, size_t len) {
   size_t buflen = 1+len/sizeof(unsigned int);
   unsigned int number, *buf = malloc(buflen);   
   int rc = 0;
   for (size_t data_read = 0; data_read < buflen; data_read++) {      
      if (rc = rand_s(&number))
         break;
      buf[data_read] = number;
   }
   
   if (!rc)
      memcpy(salt, buf, len);

   free(buf);
   return rc ? -1 : 0;
}

#else

#ifndef S_SPLINT_S /* Including this here triggers a known bug in splint */
#include <unistd.h>
#endif

#define RNGDEV "/dev/urandom"

int libscrypt_salt_gen(uint8_t *salt, size_t len)
{
	unsigned char buf[len];
	size_t data_read = 0;
	int urandom = open(RNGDEV, O_RDONLY);

	if (urandom < 0)
	{
		return -1;
	}

	while (data_read < len) {
		ssize_t result = read(urandom, buf + data_read, len - data_read);

		if (result < 0)
		{
			if (errno == EINTR || errno == EAGAIN) {
				continue;	
			}

			else {
				(void)close(urandom);
				return -1;
			}
		}

		data_read += result;
	}

	/* Failures on close() shouldn't occur with O_RDONLY */
	(void)close(urandom);

	memcpy(salt, buf, len);

	return 0;
}

#endif
