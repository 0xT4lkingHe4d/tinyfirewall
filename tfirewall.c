#include <linux/types.h>
#include <linux/netfilter.h>
#include <linux/module.h>
#include <linux/if_ether.h>
#include <linux/ip.h>

#define pr(s)			printk(KERN_INFO "%s\n", s);
#define prf(s, ...)		printk(KERN_INFO s, __VA_ARGS__);

static void tfw_register(void);
static void tfw_unregister(void);

#define DEV_NAME	"tfirewall"
#define FW_DEFAULT_SIZE		0x10

#define TFW_ADD_RULE 1
#define TFW_DEL_RULE 2
enum fw_act_t { FWActDeny=0, FWActAllow=1, };

typedef struct {
	__u32	src_ip, dst_ip;
	__u8	src_mask, dst_mask;
	enum fw_act_t act;
} user_fw_rule_t;

typedef struct {
	user_fw_rule_t	user;
	int active;
} fw_rule_t;

typedef struct {
	fw_rule_t	*rules;
	__u16		num;
	__u16		free;
	__u8		dflt_act;
} tfw_t;

static tfw_t fw = {0};

#define fw_each_rule(fw, r)		\
		for (fw_rule_t *r = (fw)->rules; (void*)r < (void*)&(fw)->rules[(fw)->num]; r++)

#define mask(bits, v)	((-1ull << (bits)) & bits)
#define ipv4_cmp(a, b, mask_bits)		\
		mask((a), (mask_bits)) == mask((b), (mask_bits))

static unsigned int
my_hook(void *ptr, struct sk_buff *skb, const struct nf_hook_state *state) {
	struct iphdr *iph = ip_hdr(skb);
	char *i_src = (char*)&iph->saddr;
	char *i_dst = (char*)&iph->daddr;

	fw_each_rule(&fw, r) if (r->active) {
		if ((!r->src_ip || mask(r->src_ip, iph->saddr, r->src_mask)) &&
			(!r->dst_ip || mask(r->dst_ip, iph->daddr, r->dst_mask)))
		{
			switch (r->act) {
				case FWActDeny:		return NF_DROP;
				case FWActAllow:	return NF_ACCEPT;
				default:
					return fw.dflt_act;
			}
		}
	}
	
	return NF_ACCEPT;
}


static struct nf_hook_ops hk_ops = {
	.hook 		= my_hook,
	.pf 		= NFPROTO_IPV4,
	.hooknum	= NF_INET_POST_ROUTING,
};

int tfw_open(struct inode *inode, struct file *f) {
	return 0;
}

long tfw_ioctl(struct file *f, unsigned int cmd, unsigned long arg) {
	fw_rule_t rule = { .active=1 };
	void __user *argp = (void __user*)arg;
	copy_from_user(&rule.user, argp, sizeof(user_fw_rule_t));

	switch (cmd) {
		case TFW_ADD_RULE:
		{
			if (!fw.free) {
				__u16 num = (fw.num + FW_DEFAULT_SIZE);
				fw.rules = krealloc(fw.rules, num * sizeof(fw_rule_t), GFP_KERNEL);
				fw.free += FW_DEFAULT_SIZE;
			}
			memcpy(&fw.rules[fw.num++], &rule, sizeof(fw_rule_t));
			--fw.free;		
		};
		break;
		case TFW_DEL_RULE:
		{
			fw_each_rule(&fw, r) if (r->active)
				if (!memcmp(&r->user, &rule.user, sizeof(user_fw_rule_t)))
					r->active = 0;			
		}
		break;
	}

	return 0;
}

static struct file_operations tfw_fops = {
	.owner			= THIS_MODULE,
	.open			= tfw_open,
	.unlocked_ioctl = tfw_ioctl,
};


typedef struct {
	unsigned int major, minor;
	struct class	*class;
	struct device	*device;
	char			nf_hooked;
} tfw_dev_t;


static tfw_dev_t hey = {0};

static int tfw_init(void) {
	dev_t dev=0;
	
	tfw_register();
	hey.major = register_chrdev(0, DEV_NAME, &tfw_fops);
	if (hey.major < 0) goto err;
	dev = MKDEV(hey.major, hey.minor);

	hey.class = class_create(THIS_MODULE, "TFWKlass");
	if (IS_ERR(hey.class))
		goto err;

	hey.device = device_create(hey.class, NULL, dev, NULL, DEV_NAME);
	if (IS_ERR(hey.device))
		goto err;

	nf_register_net_hook(&init_net, &hk_ops);
	hey.nf_hooked = 1;

	return 0;
	err:
		tfw_unregister();
		printk(KERN_ERR "Failed to register chrdev\n");
		return -1;
}

static void tfw_register(void) {
	void *mem = kmalloc(sizeof(fw_rule_t) * FW_DEFAULT_SIZE, GFP_KERNEL);

	fw = (tfw_t){
		.rules		= mem,
		.free		= FW_DEFAULT_SIZE,
		.dflt_act	= NF_ACCEPT,
	};
}

static void tfw_unregister(void) {
	if (!!hey.nf_hooked)nf_unregister_net_hook(&init_net, &hk_ops);
	if (!!hey.device)	device_destroy(hey.class, MKDEV(hey.major, hey.minor));
	if (!!hey.major)	unregister_chrdev(hey.major, DEV_NAME);
	if (!!hey.class)	class_destroy(hey.class);
	kfree(fw.rules);
}

static void tfw_exit(void) {
	tfw_unregister();
}

MODULE_LICENSE("GPL");
module_init(tfw_init);
module_exit(tfw_exit);
