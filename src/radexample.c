/*
 * Copyright (C) 1995,1996,1997 Lars Fenneberg
 * Copyright (C) 2015 Nikos Mavrogiannopoulos
 *
 * See the file COPYRIGHT for the respective terms and conditions.
 *
 */

#include	<config.h>
#include	<stdio.h>
#include	<string.h>
#include	<radcli/radcli.h>

#include	<time.h>

int get_time() {
	struct timespec ts;
	struct tm tm;

	clock_gettime(CLOCK_REALTIME, &ts);
	localtime_r(&ts.tv_sec, &tm);
	printf("tv_sec=%ld  tv_nsec=%ld\n",ts.tv_sec,ts.tv_nsec);
	printf("%d/%02d/%02d %02d:%02d:%02d.%09ld\n",
		tm.tm_year+1900,
		tm.tm_mon+1,
		tm.tm_mday,
		tm.tm_hour,
		tm.tm_min,
		tm.tm_sec,
		ts.tv_nsec);
	return(0);
}

int main (void)
{
	int             result;
	char		username[128];
	char            passwd[AUTH_PASS_LEN + 1];
	VALUE_PAIR 	*send, *received;
	uint32_t	service;
	rc_handle	*rh;

	int 		total_number = 1000;
        int		count = 0;

        char    	base_user[] = "username";
        char		base_pass[] = "password";
        char		user[total_number][100];
        char		pass[total_number][100];
        char		number[100];
        
        service = PW_AUTHENTICATE_ONLY;

	/* Not needed if you already used openlog() */
	rc_openlog("my-prog-name");

	if ((rh = rc_read_config(RC_CONFIG_FILE)) == NULL)
		return ERROR_RC;
        int i;
        for (i=0; i<total_number; i = i + 1) {
		sprintf(number,"%05d",i);
		strcpy(user[i],base_user);
		strcpy(pass[i],base_pass);
		strcat(user[i],number);
		strcat(pass[i],number);
	}

	printf("start\n");
	get_time();

        for (i=0; i<total_number; i = i + 1) {
                /*
		strcpy(username, user[i]);
		strcpy(passwd, pass[i]);
                 */

		send = NULL;
        	received = NULL;

		/*
		 * Fill in User-Name
		 */
		if (rc_avpair_add(rh, &send, PW_USER_NAME, user[i], -1, 0) == NULL)
			return ERROR_RC;

		/*
		 * Fill in User-Password
		 */
		if (rc_avpair_add(rh, &send, PW_USER_PASSWORD, pass[i], -1, 0) == NULL)
			return ERROR_RC;

		/*
		 * Fill in Service-Type
		 */
		if (rc_avpair_add(rh, &send, PW_SERVICE_TYPE, &service, -1, 0) == NULL)
			return ERROR_RC;

		result = rc_auth(rh, 0, send, &received, NULL);

		if (result == OK_RC) {
                        /*
			VALUE_PAIR *vp = received;
			char name[128];
			char value[128];

			fprintf(stderr, "\"%s\" RADIUS Authentication OK\n", username);
                         */
			count = count + 1;
			/* print the known attributes in the reply */
                        /*
			while(vp != NULL) {
				if (rc_avpair_tostr(rh, vp, name, sizeof(name), value, sizeof(value)) == 0) {
					fprintf(stderr, "%s:\t%s\n", name, value);
				}
				vp = vp->next;
			}
                         */
		} else {
			fprintf(stderr, "\"%s\" RADIUS Authentication failure (RC=%i)\n", username, result);
		}
	}
	printf("end\n");
	get_time();
	printf("%d\n",count);
}
