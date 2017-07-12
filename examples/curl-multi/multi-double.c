/***************************************************************************
 *                                  _   _ ____  _
 *  Project                     ___| | | |  _ \| |
 *                             / __| | | | |_) | |
 *                            | (__| |_| |  _ <| |___
 *                             \___|\___/|_| \_\_____|
 *
 * Copyright (C) 1998 - 2016, Daniel Stenberg, <daniel@haxx.se>, et al.
 *
 * This software is licensed as described in the file COPYING, which
 * you should have received as part of this distribution. The terms
 * are also available at https://curl.haxx.se/docs/copyright.html.
 *
 * You may opt to use, copy, modify, merge, publish, distribute and/or sell
 * copies of the Software, and permit persons to whom the Software is
 * furnished to do so, under the terms of the COPYING file.
 *
 * This software is distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY
 * KIND, either express or implied.
 *
 ***************************************************************************/

/* Simplified and extended version of the multi-double example for libcurl.
 * Demonstrates the use of the CURLOPT_MUACC_INTENT option in connection with
 * the experimental modified version of libcurl with libmuacc-client support
 * through muacc_ai_getaddrinfo. */


#include <stdio.h>
#include <string.h>
#include <stdbool.h>
#include <sys/time.h>
#include <unistd.h>

#include <curl/curl.h>

/* Extension to curl/curl.h: Add support for CURLOPT_MUACC_INTENT option for
 * curl_easy_setopt. This makes it possible to use the unmodified public header
 * of libcurl. (Interesting fact: The ABI of libcurl was not modified!) */
#define CURLOPT_MUACC_INTENT (10000+245)

 /* Extension to curl/curl.h: Make sure the curl_easy_setopt call be called
 * with multiple (variable) arguments. For some reason this has been
 * deactivated through a macro by default. */
#undef curl_easy_setopt

#include <muacc/intents.h>

/* Download two files via HTTP */
int main(void) {
  CURL *http_handle_A, *http_handle_B;

  CURLM *multi_handle = curl_multi_init();

  /* Add Task A: Retrieve http://www.example.com */
  http_handle_A = curl_easy_init();
  curl_easy_setopt(http_handle_A, CURLOPT_URL, "http://www.example.com");
  static int intent_val=INTENT_STREAM;
  curl_easy_setopt(http_handle_A, CURLOPT_MUACC_INTENT, INTENT_CATEGORY, &intent_val, sizeof(int), 0);
  curl_multi_add_handle(multi_handle, http_handle_A);

  /* Add Task B: Retrieve http://www.tu-berlin.de */
  http_handle_B = curl_easy_init();
  curl_easy_setopt(http_handle_B, CURLOPT_URL, "http://www.tu-berlin.de/");
  curl_multi_add_handle(multi_handle, http_handle_B);


  int still_running; /* keep number of running handles */
  do {
    struct timeval timeout;
    bool use_timeout;
    int ret; /* select() return code */
    CURLMcode mc; /* curl_multi_fdset() return code */

    fd_set fdread;
    fd_set fdwrite;
    fd_set fdexcep;
    int maxfd = -1;

    long curl_timeo = -1;

    FD_ZERO(&fdread);
    FD_ZERO(&fdwrite);
    FD_ZERO(&fdexcep);

    curl_multi_timeout(multi_handle, &curl_timeo);
    if(curl_timeo>=0) {
      use_timeout=true;
      timeout.tv_sec = curl_timeo / 1000;
      timeout.tv_usec = (curl_timeo % 1000) * 1000;
    } else {
      use_timeout=false;
    }

    /* get file descriptors from the transfers */
    mc = curl_multi_fdset(multi_handle, &fdread, &fdwrite, &fdexcep, &maxfd);

    if(mc != CURLM_OK) {
      fprintf(stderr, "curl_multi_fdset() failed, code %d.\n", mc);
      break;
    }

    ret = select(maxfd+1, &fdread, &fdwrite, &fdexcep, use_timeout?&timeout:NULL);

    if(ret==-1) {
      perror("Select error");
      return 1;
    }
    
    /* Do more work */
    curl_multi_perform(multi_handle, &still_running);
      
  } while(still_running);

  curl_multi_cleanup(multi_handle);

  curl_easy_cleanup(http_handle_A);
  curl_easy_cleanup(http_handle_B);

  return 0;
}
