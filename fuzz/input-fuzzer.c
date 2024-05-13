/*
 * Copyright (c) 2020 Sergey Nizovtsev <snizovtsev@gmail.com>
 *
 * Permission to use, copy, modify, and distribute this software for any
 * purpose with or without fee is hereby granted, provided that the above
 * copyright notice and this permission notice appear in all copies.
 *
 * THE SOFTWARE IS PROVIDED "AS IS" AND THE AUTHOR DISCLAIMS ALL WARRANTIES
 * WITH REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF
 * MERCHANTABILITY AND FITNESS. IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR
 * ANY SPECIAL, DIRECT, INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES
 * WHATSOEVER RESULTING FROM LOSS OF MIND, USE, DATA OR PROFITS, WHETHER
 * IN AN ACTION OF CONTRACT, NEGLIGENCE OR OTHER TORTIOUS ACTION, ARISING
 * OUT OF OR IN CONNECTION WITH THE USE OR PERFORMANCE OF THIS SOFTWARE.
 */

#include <stddef.h>
#include <assert.h>
#include <fcntl.h>

#include "tmux.h"

#define FUZZER_MAXLEN 512  // Define maximum input length as 512 bytes; inputs exceeding this will be ignored.
#define PANE_WIDTH 80      // Define the width of a tmux pane.
#define PANE_HEIGHT 25     // Define the height of a tmux pane.

struct event_base *libevent;  // Declare a pointer to an event_base structure for event-driven logic.

int
LLVMFuzzerTestOneInput(const u_char *data, size_t size)
{
    struct bufferevent	*vpty[2];  // Declare an array for buffer events to simulate pane input and output.
    struct window		*w;        // Declare a pointer to a window structure.
    struct window_pane 	*wp;       // Declare a pointer to a pane structure.
    int			 error;       // Variable to store error status.

	/*
	 * Since AFL doesn't support -max_len paramenter we have to
	 * discard long inputs manually.
	 */
	if (size > FUZZER_MAXLEN)
        return 0;  // If input size exceeds the defined maximum, the input is not processed.

    w = window_create(PANE_WIDTH, PANE_HEIGHT, 0, 0);  // Create a new window.
    wp = window_add_pane(w, NULL, 0, 0);  // Add a new pane to the created window.
    bufferevent_pair_new(libevent, BEV_OPT_CLOSE_ON_FREE, vpty);  // Create a pair of associated buffer events.
    wp->ictx = input_init(wp, vpty[0], NULL);  // Initialize the input context for the pane, linking it to the buffer event.
    window_add_ref(w, __func__);  // Increase the reference count of the window to prevent deletion while in use.

    wp->fd = open("/dev/null", O_WRONLY);  // Open /dev/null device to discard any output.
    if (wp->fd == -1)
        errx(1, "open(\"/dev/null\") failed");  // Exit program if opening fails.
    wp->event = bufferevent_new(wp->fd, NULL, NULL, NULL, NULL);  // Create a buffer event for the pane's associated file descriptor.

    input_parse_buffer(wp, (u_char *)data, size);  // Parse input data and process it through the pane's input context.
    while (cmdq_next(NULL) != 0)
        ;  // Process all commands in the queue until there are no more.
    error = event_base_loop(libevent, EVLOOP_NONBLOCK);  // Execute a non-blocking event loop to handle all related events.
    if (error == -1)
        errx(1, "event_base_loop failed");  // Exit program if event loop execution fails.

    assert(w->references == 1);  // Assert that the window's reference count is 1 to ensure no memory leaks.
    window_remove_ref(w, __func__);  // Decrease the window's reference count and free it if the count reaches zero.

    bufferevent_free(vpty[0]);  // Free the buffer event.
    bufferevent_free(vpty[1]);  // Free the buffer event.

    return 0;  // Return 0 to indicate the fuzz test case is completed.
}

int
LLVMFuzzerInitialize(__unused int *argc, __unused char ***argv)
{
	const struct options_table_entry	*oe;

    global_environ = environ_create();  // Create a global environment.
    global_options = options_create(NULL);  // Create global options.
    global_s_options = options_create(NULL);  // Create session-level options.
    global_w_options = options_create(NULL);  // Create window-level options.
    for (oe = options_table; oe->name != NULL; oe++) {
        if (oe->scope & OPTIONS_TABLE_SERVER)
            options_default(global_options, oe);
        if (oe->scope & OPTIONS_TABLE_SESSION)
            options_default(global_s_options, oe);
        if (oe->scope & OPTIONS_TABLE_WINDOW)
            options_default(global_w_options, oe);
    }
    libevent = osdep_event_init();  // Initialize the event handling library.

    options_set_number(global_w_options, "monitor-bell", 0);  // Disable bell monitoring.
    options_set_number(global_w_options, "allow-rename", 1);  // Allow renaming.
    options_set_number(global_options, "set-clipboard", 2);  // Set clipboard behavior.
    socket_path = xstrdup("dummy");  // Set a dummy socket path.

    return 0;  // Initialization complete, return 0.
}
