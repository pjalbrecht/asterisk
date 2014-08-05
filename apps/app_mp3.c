/*
 * Asterisk -- An open source telephony toolkit.
 *
 * Copyright (C) 1999 - 2005, Digium, Inc.
 *
 * Mark Spencer <markster@digium.com>
 *
 * See http://www.asterisk.org for more information about
 * the Asterisk project. Please do not directly contact
 * any of the maintainers of this project for assistance;
 * the project provides a web site, mailing lists and IRC
 * channels for your use.
 *
 * This program is free software, distributed under the terms of
 * the GNU General Public License Version 2. See the LICENSE file
 * at the top of the source tree.
 */

/*! \file
 *
 * \brief Silly application to play an MP3 file -- uses mpg123
 *
 * \author Mark Spencer <markster@digium.com>
 * 
 * \ingroup applications
 */
 
/*** MODULEINFO
	<depend>working_fork</depend>
 ***/

#include "asterisk.h"

ASTERISK_FILE_VERSION(__FILE__, "$Revision: 238009 $")

#include <string.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/time.h>
#ifdef HAVE_CAP
#include <sys/capability.h>
#endif /* HAVE_CAP */
#ifdef	HAVE_CLOEXEC
#include <sys/socket.h>
#include <sys/un.h>
#include <errno.h>
#endif

#include "asterisk/lock.h"
#include "asterisk/file.h"
#include "asterisk/logger.h"
#include "asterisk/channel.h"
#include "asterisk/frame.h"
#include "asterisk/pbx.h"
#include "asterisk/module.h"
#include "asterisk/translate.h"
#include "asterisk/options.h"

#define LOCAL_MPG_123 "/usr/local/bin/mpg123"
#define MPG_123 "/usr/bin/mpg123"

static char *app = "MP3Player";

static char *synopsis = "Play an MP3 file or stream";

static char *descrip = 
"  MP3Player(location) Executes mpg123 to play the given location,\n"
"which typically would be a filename or a URL. User can exit by pressing\n"
"any key on the dialpad, or by hanging up."; 


#ifdef	HAVE_CLOEXEC
static int mp3play(char *filename, struct sockaddr_un ast_address)
#else
static int mp3play(char *filename, int fd)
#endif
{
	int res;
	sigset_t fullset, oldset;
#ifdef HAVE_CAP
	cap_t cap;
#endif

	sigfillset(&fullset);
	pthread_sigmask(SIG_BLOCK, &fullset, &oldset);

	res = fork();
	if (res < 0) 
		ast_log(LOG_WARNING, "Fork failed\n");
	if (res) {
		pthread_sigmask(SIG_SETMASK, &oldset, NULL);
		return res;
	}
#ifdef HAVE_CAP
	cap = cap_from_text("cap_net_admin-eip");

	if (cap_set_proc(cap)) {
		/* Careful with order! Logging cannot happen after we close FDs */
		ast_log(LOG_WARNING, "Unable to remove capabilities.\n");
	}
	cap_free(cap);
#endif
	if (ast_opt_high_priority)
		ast_set_priority(0);
	signal(SIGPIPE, SIG_DFL);
	pthread_sigmask(SIG_UNBLOCK, &fullset, NULL);

#ifdef	HAVE_CLOEXEC
	//
	// create and connect unix socket file descriptors
	//
	int mp3_sock;
	if ((mp3_sock = socket(AF_UNIX, SOCK_DGRAM, 0)) < 0) {
		ast_log(LOG_ERROR, "unable to create mp3 socket: %s\n", strerror(errno));
		_exit(1);
	}

	if(connect(mp3_sock, (const struct sockaddr *) &ast_address, sizeof(struct sockaddr_un)) != 0) {
		ast_log(LOG_ERROR, "unable to connect mp3 socket: %s\n", strerror(errno));
		_exit(1);
	}

	//
	// create pipe for mp3 program
	//
	int mp3_fds[2];
	if (pipe(mp3_fds)) {
		ast_log(LOG_ERROR, "unable to create mp3 pipe: %s\n", strerror(errno));
		_exit(1);
	}

	//
	// send mp3 file descriptor to asterisk
	//

	char mp3_buf[CMSG_SPACE(1 * sizeof(int))] = { 0, };

	struct msghdr mp3_message = { .msg_control = mp3_buf, .msg_controllen = sizeof mp3_buf };

	struct cmsghdr *mp3_cmsg = CMSG_FIRSTHDR(&mp3_message);
	mp3_cmsg->cmsg_level = SOL_SOCKET;
	mp3_cmsg->cmsg_type = SCM_RIGHTS;
	mp3_cmsg->cmsg_len = CMSG_LEN(1 * sizeof(int));

	int *mp3_cmsg_fds_ptr = (int *)CMSG_DATA(mp3_cmsg);
	memcpy(mp3_cmsg_fds_ptr, &mp3_fds[0], 1 * sizeof(int));

	if (sendmsg(mp3_sock, &mp3_message, 0) < 0) {
		ast_log(LOG_ERROR, "mp3 fds sendmsg failed: %s\n", strerror(errno));
		_exit(1);
	}

	close(mp3_sock);

	dup2(mp3_fds[1], STDOUT_FILENO);

	close(mp3_fds[0]);
	close(mp3_fds[1]);
#else
	dup2(fd, STDOUT_FILENO);
	int x;
	for (x=STDERR_FILENO + 1;x<256;x++) {
		close(x);
	}
#endif
	/* Execute mpg123, but buffer if it's a net connection */
	if (!strncasecmp(filename, "http://", 7)) {
		/* Most commonly installed in /usr/local/bin */
	    execl(LOCAL_MPG_123, "mpg123", "-q", "-s", "-b", "1024", "-f", "8192", "--mono", "-r", "8000", filename, (char *)NULL);
		/* But many places has it in /usr/bin */
	    execl(MPG_123, "mpg123", "-q", "-s", "-b", "1024","-f", "8192", "--mono", "-r", "8000", filename, (char *)NULL);
		/* As a last-ditch effort, try to use PATH */
	    execlp("mpg123", "mpg123", "-q", "-s", "-b", "1024",  "-f", "8192", "--mono", "-r", "8000", filename, (char *)NULL);
	}
	else {
		/* Most commonly installed in /usr/local/bin */
	    execl(MPG_123, "mpg123", "-q", "-s", "-f", "8192", "--mono", "-r", "8000", filename, (char *)NULL);
		/* But many places has it in /usr/bin */
	    execl(LOCAL_MPG_123, "mpg123", "-q", "-s", "-f", "8192", "--mono", "-r", "8000", filename, (char *)NULL);
		/* As a last-ditch effort, try to use PATH */
	    execlp("mpg123", "mpg123", "-q", "-s", "-f", "8192", "--mono", "-r", "8000", filename, (char *)NULL);
	}
	ast_log(LOG_WARNING, "Execute of mpg123 failed\n");
	_exit(0);
}

static int timed_read(int fd, void *data, int datalen, int timeout)
{
	int res;
	struct pollfd fds[1];
	fds[0].fd = fd;
	fds[0].events = POLLIN;
	res = ast_poll(fds, 1, timeout);
	if (res < 1) {
		ast_log(LOG_NOTICE, "Poll timed out/errored out with %d\n", res);
		return -1;
	}
	return read(fd, data, datalen);
	
}

static int mp3_exec(struct ast_channel *chan, void *data)
{
	int res=0;
	struct ast_module_user *u;
	int fds[2];
	int ms = -1;
	int pid = -1;
	int owriteformat;
	int timeout = 2000;
	struct timeval next;
	struct ast_frame *f;
	struct myframe {
		struct ast_frame f;
		char offset[AST_FRIENDLY_OFFSET];
		short frdata[160];
	} myf = {
		.f = { 0, },
	};

	if (ast_strlen_zero(data)) {
		ast_log(LOG_WARNING, "MP3 Playback requires an argument (filename)\n");
		return -1;
	}

	u = ast_module_user_add(chan);
	
	ast_stopstream(chan);

	owriteformat = chan->writeformat;
	res = ast_set_write_format(chan, AST_FORMAT_SLINEAR);
	if (res < 0) {
		ast_log(LOG_WARNING, "Unable to set write format to signed linear\n");
		ast_module_user_remove(u);
		return -1;
	}

#ifdef	HAVE_CLOEXEC
	//
	// create and bind unix socket for file descriptors
	//
	int ast_sock;
	if ((ast_sock = socket(AF_UNIX, SOCK_DGRAM | SOCK_CLOEXEC, 0)) < 0) {
		ast_log(LOG_ERROR, "unable to create ast socket: %s\n", strerror(errno));
		ast_set_write_format(chan, owriteformat);
		ast_module_user_remove(u);
		return -1;
	}

	struct sockaddr_un ast_address;
	ast_address.sun_family = AF_UNIX;
	sprintf(ast_address.sun_path, "/tmp/asterisk-%s",chan->uniqueid);

	if(bind(ast_sock, (const struct sockaddr *) &ast_address, sizeof(struct sockaddr_un)) != 0) {
		ast_log(LOG_ERROR, "ast_sock bind failed, %s\n", strerror(errno));
		ast_set_write_format(chan, owriteformat);
		close(ast_sock);
		ast_module_user_remove(u);
		return -1;
	}

	//
	// create the process for media playback
	//
	if (((res = mp3play((char *)data, ast_address)) < 0)) {
		ast_log(LOG_WARNING, "Unable to fork child process\n");
		ast_set_write_format(chan, owriteformat);
		close(ast_sock);
		ast_module_user_remove(u);
		return -1;
	}

	//
	// receive file descriptors from mp3 process
	//

	char ast_buf[CMSG_SPACE(1 * sizeof(int))] = { 0, };

	struct msghdr ast_message = { .msg_control = ast_buf, .msg_controllen = sizeof ast_buf };

	if (recvmsg(ast_sock, &ast_message, MSG_CMSG_CLOEXEC) < 0) {
		ast_log(LOG_ERROR, "ast fds recvmsg failed: %s\n", strerror(errno));
		ast_set_write_format(chan, owriteformat);
		close(ast_sock);
		ast_module_user_remove(u);
		return -1;
	}

	struct cmsghdr *ast_cmsg = CMSG_FIRSTHDR(&ast_message);
	memcpy(fds,CMSG_DATA(ast_cmsg),1 * sizeof(int));

	close(ast_sock);

	unlink(ast_address.sun_path);
#else
	if (pipe(fds)) {
		ast_log(LOG_WARNING, "Unable to create pipe\n");
		ast_module_user_remove(u);
		return -1;
	}
	
	res = mp3play((char *)data, fds[1]);
	close(fds[1]);
#endif

	if (!strncasecmp((char *)data, "http://", 7)) {
		timeout = 10000;
	}
	/* Wait 1000 ms first */
	next = ast_tvnow();
	next.tv_sec += 1;
	if (res >= 0) {
		pid = res;
		/* Order is important -- there's almost always going to be mp3...  we want to prioritize the
		   user */
		for (;;) {
			ms = ast_tvdiff_ms(next, ast_tvnow());
			if (ms <= 0) {
				res = timed_read(fds[0], myf.frdata, sizeof(myf.frdata), timeout);
				if (res > 0) {
					myf.f.frametype = AST_FRAME_VOICE;
					myf.f.subclass = AST_FORMAT_SLINEAR;
					myf.f.datalen = res;
					myf.f.samples = res / 2;
					myf.f.mallocd = 0;
					myf.f.offset = AST_FRIENDLY_OFFSET;
					myf.f.src = __PRETTY_FUNCTION__;
					myf.f.delivery.tv_sec = 0;
					myf.f.delivery.tv_usec = 0;
					myf.f.data = myf.frdata;
					if (ast_write(chan, &myf.f) < 0) {
						res = -1;
						break;
					}
				} else {
					ast_log(LOG_DEBUG, "No more mp3\n");
					res = 0;
					break;
				}
				next = ast_tvadd(next, ast_samp2tv(myf.f.samples, 8000));
			} else {
				ms = ast_waitfor(chan, ms);
				if (ms < 0) {
					ast_log(LOG_DEBUG, "Hangup detected\n");
					res = -1;
					break;
				}
				if (ms) {
					f = ast_read(chan);
					if (!f) {
						ast_log(LOG_DEBUG, "Null frame == hangup() detected\n");
						res = -1;
						break;
					}
					if (f->frametype == AST_FRAME_DTMF) {
						ast_log(LOG_DEBUG, "User pressed a key\n");
						ast_frfree(f);
						res = 0;
						break;
					}
					ast_frfree(f);
				} 
			}
		}
	}
	close(fds[0]);
	
	if (pid > -1)
		kill(pid, SIGKILL);
	if (!res && owriteformat)
		ast_set_write_format(chan, owriteformat);

	ast_module_user_remove(u);
	
	return res;
}

static int unload_module(void)
{
	int res;

	res = ast_unregister_application(app);

	ast_module_user_hangup_all();
	
	return res;
}

static int load_module(void)
{
	return ast_register_application(app, mp3_exec, synopsis, descrip);
}

AST_MODULE_INFO_STANDARD(ASTERISK_GPL_KEY, "Silly MP3 Application");
