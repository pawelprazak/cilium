/*
 *  Copyright (C) 2016-2018 Authors of Cilium
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
 */
#include <node_config.h>
#include <netdev_config.h>

/* These are configuartion options which have a default value in their
 * respective header files and must thus be defined beforehand:
 *
 * Pass unknown ICMPv6 NS to stack */
#define ACTION_UNKNOWN_ICMP6_NS TC_ACT_OK

/* Include policy_can_access_ingress() */
#define REQUIRES_CAN_ACCESS

#include <bpf/api.h>

#include <stdint.h>
#include <stdio.h>

#include "lib/utils.h"
#include "lib/common.h"
#include "lib/arp.h"
#include "lib/maps.h"
#include "lib/ipv6.h"
#include "lib/ipv4.h"
#include "lib/icmp6.h"
#include "lib/eth.h"
#include "lib/dbg.h"
#include "lib/trace.h"
#include "lib/l3.h"
#include "lib/l4.h"
#include "lib/policy.h"
#include "lib/drop.h"
#include "lib/encap.h"
#include "lib/nat.h"
#include "lib/ingress.h"

static __always_inline int do_netdev(struct __sk_buff *skb, __u16 proto)
{
	__u32 identity = 0;
	int ret;

#ifdef ENABLE_IPSEC
	if (1) {
		__u32 magic = skb->mark & MARK_MAGIC_HOST_MASK;

		if (magic == MARK_MAGIC_ENCRYPT) {
			__u32 seclabel, tunnel_endpoint = 0;

			seclabel = get_identity(skb);
			tunnel_endpoint = skb->cb[4];
			skb->mark = 0;
			bpf_clear_cb(skb);

#ifdef ENCAP_IFINDEX
			return __encap_and_redirect_with_nodeid(skb, tunnel_endpoint, seclabel, TRACE_PAYLOAD_LEN);
#endif
			return TC_ACT_OK;
		}
	}
#endif
	bpf_clear_cb(skb);

#ifdef FROM_HOST
	if (1) {

#ifdef HOST_REDIRECT_TO_INGRESS
	if (proto == bpf_htons(ETH_P_ARP)) {
		union macaddr mac = HOST_IFINDEX_MAC;
		return arp_respond(skb, &mac, BPF_F_INGRESS);
	}
#endif

		int trace = TRACE_FROM_HOST;
		bool from_proxy;

		from_proxy = handle_identity_from_host(skb, &identity);
		if (from_proxy)
			trace = TRACE_FROM_PROXY;
		send_trace_notify(skb, trace, identity, 0, 0,
				  skb->ingress_ifindex, 0, TRACE_PAYLOAD_LEN);
	}
#else
	send_trace_notify(skb, TRACE_FROM_STACK, 0, 0, 0, skb->ingress_ifindex,
			  0, TRACE_PAYLOAD_LEN);
#endif

	switch (proto) {
#ifdef ENABLE_IPV6
	case bpf_htons(ETH_P_IPV6):
		/* This is considered the fast path, no tail call */
		ret = handle_ipv6(skb, identity);

		/* We should only be seeing an error here for packets which have
		 * been targetting an endpoint managed by us. */
		if (IS_ERR(ret))
			return send_drop_notify_error(skb, ret, TC_ACT_SHOT, METRIC_INGRESS);
		break;
#endif

#ifdef ENABLE_IPV4
	case bpf_htons(ETH_P_IP):
		skb->cb[CB_SRC_IDENTITY] = identity;
		ep_tail_call(skb, CILIUM_CALL_IPV4_FROM_LXC);
		/* We are not returning an error here to always allow traffic to
		 * the stack in case maps have become unavailable.
		 *
		 * Note: Since drop notification requires a tail call as well,
		 * this notification is unlikely to succeed. */
		return send_drop_notify_error(skb, DROP_MISSED_TAIL_CALL,
		                              TC_ACT_OK, METRIC_INGRESS);

#endif

	default:
		/* Pass unknown traffic to the stack */
		ret = TC_ACT_OK;
	}

	return ret;
}

__section("from-netdev")
int from_netdev(struct __sk_buff *skb)
{
	__u16 proto;

	if (!validate_ethertype(skb, &proto))
		/* Pass unknown traffic to the stack */
		return TC_ACT_OK;

	return do_netdev(skb, proto);
}

__section("masq")
int do_masq(struct __sk_buff *skb)
{
	__u16 proto;
	int ret;

	if (!validate_ethertype(skb, &proto))
		/* Pass unknown traffic to the stack */
		return TC_ACT_OK;

	cilium_dbg_capture(skb, DBG_CAPTURE_SNAT_PRE, skb->ifindex);
	ret = snat_process(skb, BPF_PKT_DIR);
	if (!ret)
		cilium_dbg_capture(skb, DBG_CAPTURE_SNAT_POST, skb->ifindex);
	return ret;
}

__section("masq-pre")
int do_masq_pre(struct __sk_buff *skb)
{
	__u16 proto;
	int ret;

	if (!validate_ethertype(skb, &proto))
		/* Pass unknown traffic to the stack */
		return TC_ACT_OK;

	cilium_dbg_capture(skb, DBG_CAPTURE_SNAT_PRE, skb->ifindex);
	ret = snat_process(skb, BPF_PKT_DIR);
	if (!ret) {
		cilium_dbg_capture(skb, DBG_CAPTURE_SNAT_POST, skb->ifindex);
		ret = do_netdev(skb, proto);
	}
	return ret;
}

__section("masq-post")
int do_masq_post(struct __sk_buff *skb)
{
	__u16 proto;
	int ret;

	if (!validate_ethertype(skb, &proto))
		/* Pass unknown traffic to the stack */
		return TC_ACT_OK;

	ret = do_netdev(skb, proto);
	if (!ret) {
		cilium_dbg_capture(skb, DBG_CAPTURE_SNAT_PRE, skb->ifindex);
		ret = snat_process(skb, BPF_PKT_DIR);
		if (!ret)
			cilium_dbg_capture(skb, DBG_CAPTURE_SNAT_POST,
					   skb->ifindex);
	}
	return ret;
}

BPF_LICENSE("GPL");
