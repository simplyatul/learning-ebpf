#include <stdio.h>
#include <unistd.h>
#include <errno.h>
#include <bpf/libbpf.h>
#include "hello-buffer-config.h"
#include "hello-buffer-config.skel.h"

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	if (level >= LIBBPF_DEBUG)
		return 0;

	return vfprintf(stderr, format, args);
}

void handle_event(void *ctx, int cpu, void *data, unsigned int data_sz)
{
	struct data_t *m = data;

	printf("%-6d %-6d %-16s %-16s %s\n", m->pid, m->uid, m->command, m->path, m->message);
}

void lost_event(void *ctx, int cpu, long long unsigned int data_sz)
{
	printf("lost event\n");
}

int main()
{
    struct hello_buffer_config_bpf *skel;
    int err;
	struct perf_buffer *pb = NULL;

	libbpf_set_print(libbpf_print_fn);

	skel = hello_buffer_config_bpf__open_and_load();
	if (!skel) {
		printf("Failed to open BPF object\n");
		return 1;
	}

	err = hello_buffer_config_bpf__attach(skel);
	if (err) {
		fprintf(stderr, "Failed to attach BPF skeleton: %d\n", err);
		hello_buffer_config_bpf__destroy(skel);
        return 1;
	}

	struct user_msg_t msg_root = {.message = "Hi root !"};
	struct user_msg_t msg_1000 = {.message = "Hi user 1000 !"};
	uint32_t root_id = 0;
	uint32_t user_id = 1000;
	// update my_config 
	int ret = bpf_map__update_elem(skel->maps.my_config, &root_id, sizeof(uint32_t), &msg_root, sizeof(struct user_msg_t), 0);
	if(ret < 0) {
		fprintf(stderr, "Failed to update my_config hash map\n");
		fprintf(stderr, "error no: %d\n", errno);
	}

	ret = bpf_map__update_elem(skel->maps.my_config, &user_id, sizeof(uint32_t), &msg_1000, sizeof(struct user_msg_t), 0);
	if(ret < 0) {
		fprintf(stderr, "Failed to update my_config hash map\n");
		fprintf(stderr, "error no: %d\n", errno);
	}

	pb = perf_buffer__new(bpf_map__fd(skel->maps.output), 8, handle_event, lost_event, NULL, NULL);
	if (!pb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		hello_buffer_config_bpf__destroy(skel);
        return 1;
	}

	while (true) {
		err = perf_buffer__poll(pb, 100 /* timeout, ms */);
		// Ctrl-C gives -EINTR
		if (err == -EINTR) {
			err = 0;
			break;
		}
		if (err < 0) {
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

	perf_buffer__free(pb);
	hello_buffer_config_bpf__destroy(skel);
	return -err;
}
