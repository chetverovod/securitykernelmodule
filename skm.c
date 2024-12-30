#include <linux/init.h>
#include <linux/module.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>

#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/string.h>
#include <linux/byteorder/generic.h>


#define M_NAME "Security filter"

MODULE_LICENSE("GPL");
MODULE_AUTHOR("Plastov Igor");
MODULE_DESCRIPTION(M_NAME);
MODULE_VERSION("0.01");


/* Структура для регистрации функции перехвата входящих IP пакетов. */
struct nf_hook_ops input_bundle;

/* Структура для регистрации функции перехвата исходящих IP пакетов. */
struct nf_hook_ops output_bundle;

int parse_ip_options(uint8_t *options, size_t length)
{
    uint8_t type, len;
    size_t offset = 0;
    int res = 0; 
    size_t i;
    while (offset < length)
    {
        type = options[offset];

        if (type == 0 || type == 1)
        { 
            /* End of Option List или No Operation */
            break;
        }

        len = options[offset + 1]; /* Длина опции. */
        printk("Option Type: %hhu, Length: %hhu\n", type, len);
        if ((type == 130) || (type == 133))
        {
            printk("Security Option Type: %hhu, Length: %hhu\n", type, len);
            res = 1;

            if (len > 1)
            {
                printk("Option Data: ");
                for (i = 2; i < len; ++i)
                {
                    printk("%02X ", options[offset + i]);
                }
                printk("\n");
            }
        }
        offset += len;
    }
    return res;
}


unsigned int my_nf_hook(unsigned int hooknum,
        struct sk_buff *skb,
        const struct net_device *in,
        const struct net_device *out,
        int (*okfn)(struct sk_buff *))
{
    /* Если заголовок не содержит мандатной метки, возвращаем NF_ACCEPT,
       чтобы принять пакет. */
    int res = NF_ACCEPT;
    struct iphdr *iph; /* Указатель на заголовок IP-пакета. */

    if (skb == NULL)
    {    
       return res;
    }

    iph = ip_hdr(skb);
    if (iph == NULL)
    {    
       return res;
    }

    /* Анализа пакета. */
    if (iph->protocol == IPPROTO_TCP)
    {
        /* Обрабатываем, если это TCP-пакет. */
        uint8_t ihl = iph->ihl;
        size_t options_length = (ihl * 4) - sizeof(struct iphdr);


        if (options_length > 0)
        {
            uint8_t *options = (uint8_t *) skb->data + sizeof(struct iphdr);
            if (parse_ip_options(options, options_length))
            {	
                struct tcphdr *tcph = tcp_hdr(skb); /* Указатель на заголовок TCP-пакета. */
                printk(KERN_INFO M_NAME " TCP packet received: src=%pI4, dst=%pI4, sport=%u, dport=%u\n",
                        &iph->saddr, &iph->daddr, ntohs(tcph->source), ntohs(tcph->dest));
                printk(KERN_INFO M_NAME " packet has security options, dropped.\n");

                /* Возвращаем NF_DROP, чтобы отбросить пакет. */
                res = NF_DROP;
            }
        }
    }

    return res;
}


static int __init skm_init(void)
{
    pr_info(M_NAME " module is loaded.\n");

    /* Заполняем структуру для регистрации hook функции 
       Указываем имя функции, которая будет обрабатывать пакеты. */
    input_bundle.hook = (nf_hookfn*)my_nf_hook;

    /* Указываем, в каком месте будет срабатывать функция. */
    input_bundle.hooknum = NF_INET_PRE_ROUTING;

    /* Указываем семейство протоколов. */
    input_bundle.pf = NFPROTO_IPV4;

    /* Выставляем самый высокий приоритет для функции. */
    input_bundle.priority = NF_IP_PRI_FIRST;

    /* Заполняем структуру для регистрации hook функции 
       Указываем имя функции, которая будет обрабатывать пакеты. */
    output_bundle.hook = (nf_hookfn*)my_nf_hook;

    /* Указываем, в каком месте будет срабатывать функция. */
    output_bundle.hooknum =NF_INET_LOCAL_OUT;

    /* Указываем семейство протоколов. */
    output_bundle.pf = NFPROTO_IPV4;

    /* Выставляем самый высокий приоритет для функции. */
    output_bundle.priority = NF_IP_PRI_FIRST;


    /* Регистрируем. */
    nf_register_net_hook(&init_net, &input_bundle);
    nf_register_net_hook(&init_net, &output_bundle);
    printk(KERN_INFO M_NAME " module activated.");
    return 0;
}


static void __exit skm_exit(void)
{
    /* Удаляем из цепочки hook функцию. */
    nf_unregister_net_hook(&init_net, &input_bundle);
    printk(KERN_INFO M_NAME " module deactivated.");
}

module_init(skm_init);
module_exit(skm_exit);
