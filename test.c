#include <linux/types.h>
#include <stdio.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#define FW_ADD_RULE 1
#define FW_DEL_RULE 2
enum fw_act_t { FWActDeny=0, FWActAllow=1, };

typedef struct {
	__u32	src_ip, dst_ip;
	__u8	src_mask, dst_mask;
	enum fw_act_t act;
} fw_rule_t;

int tfw_add_rule(int fd, __u32 saddr, __u8 saddr_mask, __u32 daddr, __u8 daddr_mask, enum fw_act_t action) {
	fw_rule_t st = {
		.src_ip		= inet_addr(saddr),
		.dst_ip		= inet_addr(daddr),
		.src_mask	= saddr_mask,
		.dst_mask	= daddr_mask,
		.act		= action,
	};

	return ioctl(fd, FW_ADD_RULE, &st);
}

int main() {
	int fd = open("/dev/tfirewall", O_RDWR);
	if (fd < 0) {
		perror("[tfw]  Failed to open device");
		return -1;
	}

	if (!tfw_add_rule(fd, "142.250.74.110", 32, 0, 0, FWActDeny)) {
		perror("[tfw]  Failed to add rule");
		return -1;
	}
	puts("Rule added * -> 142.250.74.110 / 32 DENY");

	close(fd);
}
