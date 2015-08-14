/* This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License version 2
 * as published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * Authors:
 * Alexander Aring <aar@pengutronix.de>
 *
 * Based on: net/wireless/nl80211.c
 */

#include <linux/rtnetlink.h>

#include <net/cfg802154.h>
#include <net/genetlink.h>
#include <net/mac802154.h>
#include <net/netlink.h>
#include <net/nl802154.h>
#include <net/ieee802154_netdev.h>
#include <net/sock.h>

#include "nl802154.h"
#include "rdev-ops.h"
#include "core.h"

#include "../mac802154/ieee802154_i.h"

#ifndef PRIx64
#define PRIx64 "llx"
#endif

struct work802154 {
	// probably should add a mutex
	struct sk_buff *skb;
	struct genl_info *info; // user_ptr[0] = rdev, user_ptr[1] = wpan_dev
	int cmd; // selects which item in the union below to use
	union {
		// put any additional command-specific structs in here
		// note: only for information that must be conveyed e.g.
		// between REQ and CNF - not for the entire CNF or IND.
		// If you can extrapolate information from rdev, wpan_dev,
		// info, etc, do not duplicated it here.
		struct ed_scan {
			u8 channel_page;
			u32 scan_channels;
			u8 scan_duration;
		} ed_scan;
		struct disassoc {
			u16 device_panid;
			u64 device_address;
		} disassoc;
	} cmd_stuff;
	struct completion completion;
	struct delayed_work work;
};

static int nl802154_pre_doit(const struct genl_ops *ops, struct sk_buff *skb,
			     struct genl_info *info);

static void nl802154_post_doit(const struct genl_ops *ops, struct sk_buff *skb,
			       struct genl_info *info);

/* the netlink family */
static struct genl_family nl802154_fam = {
	.id = GENL_ID_GENERATE,		/* don't bother with a hardcoded ID */
	.name = NL802154_GENL_NAME,	/* have users key off the name instead */
	.hdrsize = 0,			/* no private header */
	.version = 1,			/* no particular meaning now */
	.maxattr = NL802154_ATTR_MAX,
	.netnsok = true,
	.pre_doit = nl802154_pre_doit,
	.post_doit = nl802154_post_doit,
};

/* multicast groups */
enum nl802154_multicast_groups {
	NL802154_MCGRP_CONFIG,
};

static const struct genl_multicast_group nl802154_mcgrps[] = {
	[NL802154_MCGRP_CONFIG] = { .name = "config", },
};

/* returns ERR_PTR values */
static struct wpan_dev *
__cfg802154_wpan_dev_from_attrs(struct net *netns, struct nlattr **attrs)
{
	struct cfg802154_registered_device *rdev;
	struct wpan_dev *result = NULL;
	bool have_ifidx = attrs[NL802154_ATTR_IFINDEX];
	bool have_wpan_dev_id = attrs[NL802154_ATTR_WPAN_DEV];
	u64 wpan_dev_id;
	int wpan_phy_idx = -1;
	int ifidx = -1;

	ASSERT_RTNL();

	if (!have_ifidx && !have_wpan_dev_id)
		return ERR_PTR(-EINVAL);

	if (have_ifidx)
		ifidx = nla_get_u32(attrs[NL802154_ATTR_IFINDEX]);
	if (have_wpan_dev_id) {
		wpan_dev_id = nla_get_u64(attrs[NL802154_ATTR_WPAN_DEV]);
		wpan_phy_idx = wpan_dev_id >> 32;
	}

	list_for_each_entry(rdev, &cfg802154_rdev_list, list) {
		struct wpan_dev *wpan_dev;

		/* TODO netns compare */

		if (have_wpan_dev_id && rdev->wpan_phy_idx != wpan_phy_idx)
			continue;

		list_for_each_entry(wpan_dev, &rdev->wpan_dev_list, list) {
			if (have_ifidx && wpan_dev->netdev &&
			    wpan_dev->netdev->ifindex == ifidx) {
				result = wpan_dev;
				break;
			}
			if (have_wpan_dev_id &&
			    wpan_dev->identifier == (u32)wpan_dev_id) {
				result = wpan_dev;
				break;
			}
		}

		if (result)
			break;
	}

	if (result)
		return result;

	return ERR_PTR(-ENODEV);
}

static struct cfg802154_registered_device *
__cfg802154_rdev_from_attrs(struct net *netns, struct nlattr **attrs)
{
	struct cfg802154_registered_device *rdev = NULL, *tmp;
	struct net_device *netdev;

	ASSERT_RTNL();

	if (!attrs[NL802154_ATTR_WPAN_PHY] &&
	    !attrs[NL802154_ATTR_IFINDEX] &&
	    !attrs[NL802154_ATTR_WPAN_DEV])
		return ERR_PTR(-EINVAL);

	if (attrs[NL802154_ATTR_WPAN_PHY])
		rdev = cfg802154_rdev_by_wpan_phy_idx(
				nla_get_u32(attrs[NL802154_ATTR_WPAN_PHY]));

	if (attrs[NL802154_ATTR_WPAN_DEV]) {
		u64 wpan_dev_id = nla_get_u64(attrs[NL802154_ATTR_WPAN_DEV]);
		struct wpan_dev *wpan_dev;
		bool found = false;

		tmp = cfg802154_rdev_by_wpan_phy_idx(wpan_dev_id >> 32);
		if (tmp) {
			/* make sure wpan_dev exists */
			list_for_each_entry(wpan_dev, &tmp->wpan_dev_list, list) {
				if (wpan_dev->identifier != (u32)wpan_dev_id)
					continue;
				found = true;
				break;
			}

			if (!found)
				tmp = NULL;

			if (rdev && tmp != rdev)
				return ERR_PTR(-EINVAL);
			rdev = tmp;
		}
	}

	if (attrs[NL802154_ATTR_IFINDEX]) {
		int ifindex = nla_get_u32(attrs[NL802154_ATTR_IFINDEX]);

		netdev = __dev_get_by_index(netns, ifindex);
		if (netdev) {
			if (netdev->ieee802154_ptr)
				tmp = wpan_phy_to_rdev(
						netdev->ieee802154_ptr->wpan_phy);
			else
				tmp = NULL;

			/* not wireless device -- return error */
			if (!tmp)
				return ERR_PTR(-EINVAL);

			/* mismatch -- return error */
			if (rdev && tmp != rdev)
				return ERR_PTR(-EINVAL);

			rdev = tmp;
		}
	}

	if (!rdev)
		return ERR_PTR(-ENODEV);

	/* TODO netns compare */

	return rdev;
}

/* This function returns a pointer to the driver
 * that the genl_info item that is passed refers to.
 *
 * The result of this can be a PTR_ERR and hence must
 * be checked with IS_ERR() for errors.
 */
static struct cfg802154_registered_device *
cfg802154_get_dev_from_info(struct net *netns, struct genl_info *info)
{
	return __cfg802154_rdev_from_attrs(netns, info->attrs);
}

/* policy for the attributes */
static const struct nla_policy nl802154_policy[NL802154_ATTR_MAX+1] = {
	[NL802154_ATTR_WPAN_PHY] = { .type = NLA_U32 },
	[NL802154_ATTR_WPAN_PHY_NAME] = { .type = NLA_NUL_STRING,
					  .len = 20-1 },

	[NL802154_ATTR_IFINDEX] = { .type = NLA_U32 },
	[NL802154_ATTR_IFTYPE] = { .type = NLA_U32 },
	[NL802154_ATTR_IFNAME] = { .type = NLA_NUL_STRING, .len = IFNAMSIZ-1 },

	[NL802154_ATTR_WPAN_DEV] = { .type = NLA_U64 },

	[NL802154_ATTR_PAGE] = { .type = NLA_U8, },
	[NL802154_ATTR_CHANNEL] = { .type = NLA_U8, },

	[NL802154_ATTR_TX_POWER] = { .type = NLA_S32, },

	[NL802154_ATTR_CCA_MODE] = { .type = NLA_U32, },
	[NL802154_ATTR_CCA_OPT] = { .type = NLA_U32, },
	[NL802154_ATTR_CCA_ED_LEVEL] = { .type = NLA_S32, },

	[NL802154_ATTR_SUPPORTED_CHANNEL] = { .type = NLA_U32, },

	[NL802154_ATTR_PAN_ID] = { .type = NLA_U16, },
	[NL802154_ATTR_EXTENDED_ADDR] = { .type = NLA_U64 },
	[NL802154_ATTR_SHORT_ADDR] = { .type = NLA_U16, },

	[NL802154_ATTR_MIN_BE] = { .type = NLA_U8, },
	[NL802154_ATTR_MAX_BE] = { .type = NLA_U8, },
	[NL802154_ATTR_MAX_CSMA_BACKOFFS] = { .type = NLA_U8, },

	[NL802154_ATTR_MAX_FRAME_RETRIES] = { .type = NLA_S8, },

	[NL802154_ATTR_LBT_MODE] = { .type = NLA_U8, },

	[NL802154_ATTR_WPAN_PHY_CAPS] = { .type = NLA_NESTED },

	[NL802154_ATTR_SUPPORTED_COMMANDS] = { .type = NLA_NESTED },

	[NL802154_ATTR_SCAN_STATUS] = { .type = NLA_U8, },
	[NL802154_ATTR_SCAN_TYPE] = { .type = NLA_U8, },
	[NL802154_ATTR_SCAN_DURATION] = { .type = NLA_U8, },
	[NL802154_ATTR_SCAN_RESULT_LIST_SIZE] = { .type = NLA_U8, },
	[NL802154_ATTR_SCAN_ENERGY_DETECT_LIST] = { .type = NLA_NESTED, },
	[NL802154_ATTR_SCAN_ENERGY_DETECT_LIST_ENTRY] = { .type = NLA_U8, },
	[NL802154_ATTR_SCAN_DETECTED_CATEGORY] = { .type = NLA_U8, },

	[NL802154_ATTR_SEC_LEVEL] = { .type = NLA_U8, },
	[NL802154_ATTR_SEC_KEY_ID_MODE] = { .type = NLA_U8, },
	[NL802154_ATTR_SEC_KEY_SOURCE] = { .type = NLA_NESTED, },
	[NL802154_ATTR_SEC_KEY_SOURCE_ENTRY] = { .type = NLA_U8, },
	[NL802154_ATTR_SEC_KEY_INDEX] = { .type = NLA_U8, },

	[NL802154_ATTR_ADDR_MODE] = { .type = NLA_U8, },

	[NL802154_ATTR_ASSOC_CAP_INFO] = { .type = NLA_U8, },
	[NL802154_ATTR_ASSOC_STATUS] = { .type = NLA_U8, },

	[NL802154_ATTR_BEACON_SEQUENCE_NUMBER] = { .type = NLA_U8, },
	[NL802154_ATTR_PAN_DESCRIPTOR] { .type = NLA_NESTED, },
	[NL802154_ATTR_PEND_ADDR_SPEC] = { .type = NLA_U8 },
	[NL802154_ATTR_ADDR_LIST] = { .type = NLA_NESTED },
	[NL802154_ATTR_SDU_LENGTH] = { .type = NLA_U32 },
	[NL802154_ATTR_SDU] = { .type = NLA_NESTED },
	[NL802154_ATTR_SDU_ENTRY] = { .type = NLA_U8},

	[NL802154_ATTR_DISASSOC_REASON] = { .type = NLA_U8, },
	[NL802154_ATTR_DISASSOC_TX_INDIRECT] = { .type = NLA_U8, },
	[NL802154_ATTR_DISASSOC_STATUS] = { .type = NLA_U8, },
	[NL802154_ATTR_DISASSOC_TIMEOUT_MS] = { .type = NLA_U16, },
};

/* message building helper */
static inline void *nl802154hdr_put(struct sk_buff *skb, u32 portid, u32 seq,
				    int flags, u8 cmd)
{
	/* since there is no private header just add the generic one */
	return genlmsg_put(skb, portid, seq, &nl802154_fam, flags, cmd);
}

static int
nl802154_put_flags(struct sk_buff *msg, int attr, u32 mask)
{
	struct nlattr *nl_flags = nla_nest_start(msg, attr);
	int i;

	if (!nl_flags)
		return -ENOBUFS;

	i = 0;
	while (mask) {
		if ((mask & 1) && nla_put_flag(msg, i))
			return -ENOBUFS;

		mask >>= 1;
		i++;
	}

	nla_nest_end(msg, nl_flags);
	return 0;
}

static int
nl802154_send_wpan_phy_channels(struct cfg802154_registered_device *rdev,
				struct sk_buff *msg)
{
	struct nlattr *nl_page;
	unsigned long page;

	nl_page = nla_nest_start(msg, NL802154_ATTR_CHANNELS_SUPPORTED);
	if (!nl_page)
		return -ENOBUFS;

	for (page = 0; page <= IEEE802154_MAX_PAGE; page++) {
		if (nla_put_u32(msg, NL802154_ATTR_SUPPORTED_CHANNEL,
				rdev->wpan_phy.supported.channels[page]))
			return -ENOBUFS;
	}
	nla_nest_end(msg, nl_page);

	return 0;
}

static int
nl802154_put_capabilities(struct sk_buff *msg,
			  struct cfg802154_registered_device *rdev)
{
	const struct wpan_phy_supported *caps = &rdev->wpan_phy.supported;
	struct nlattr *nl_caps, *nl_channels;
	int i;

	nl_caps = nla_nest_start(msg, NL802154_ATTR_WPAN_PHY_CAPS);
	if (!nl_caps)
		return -ENOBUFS;

	nl_channels = nla_nest_start(msg, NL802154_CAP_ATTR_CHANNELS);
	if (!nl_channels)
		return -ENOBUFS;

	for (i = 0; i <= IEEE802154_MAX_PAGE; i++) {
		if (caps->channels[i]) {
			if (nl802154_put_flags(msg, i, caps->channels[i]))
				return -ENOBUFS;
		}
	}

	nla_nest_end(msg, nl_channels);

	if (rdev->wpan_phy.flags & WPAN_PHY_FLAG_CCA_ED_LEVEL) {
		struct nlattr *nl_ed_lvls;

		nl_ed_lvls = nla_nest_start(msg,
					    NL802154_CAP_ATTR_CCA_ED_LEVELS);
		if (!nl_ed_lvls)
			return -ENOBUFS;

		for (i = 0; i < caps->cca_ed_levels_size; i++) {
			if (nla_put_s32(msg, i, caps->cca_ed_levels[i]))
				return -ENOBUFS;
		}

		nla_nest_end(msg, nl_ed_lvls);
	}

	if (rdev->wpan_phy.flags & WPAN_PHY_FLAG_TXPOWER) {
		struct nlattr *nl_tx_pwrs;

		nl_tx_pwrs = nla_nest_start(msg, NL802154_CAP_ATTR_TX_POWERS);
		if (!nl_tx_pwrs)
			return -ENOBUFS;

		for (i = 0; i < caps->tx_powers_size; i++) {
			if (nla_put_s32(msg, i, caps->tx_powers[i]))
				return -ENOBUFS;
		}

		nla_nest_end(msg, nl_tx_pwrs);
	}

	if (rdev->wpan_phy.flags & WPAN_PHY_FLAG_CCA_MODE) {
		if (nl802154_put_flags(msg, NL802154_CAP_ATTR_CCA_MODES,
				       caps->cca_modes) ||
		    nl802154_put_flags(msg, NL802154_CAP_ATTR_CCA_OPTS,
				       caps->cca_opts))
			return -ENOBUFS;
	}

	if (nla_put_u8(msg, NL802154_CAP_ATTR_MIN_MINBE, caps->min_minbe) ||
	    nla_put_u8(msg, NL802154_CAP_ATTR_MAX_MINBE, caps->max_minbe) ||
	    nla_put_u8(msg, NL802154_CAP_ATTR_MIN_MAXBE, caps->min_maxbe) ||
	    nla_put_u8(msg, NL802154_CAP_ATTR_MAX_MAXBE, caps->max_maxbe) ||
	    nla_put_u8(msg, NL802154_CAP_ATTR_MIN_CSMA_BACKOFFS,
		       caps->min_csma_backoffs) ||
	    nla_put_u8(msg, NL802154_CAP_ATTR_MAX_CSMA_BACKOFFS,
		       caps->max_csma_backoffs) ||
	    nla_put_s8(msg, NL802154_CAP_ATTR_MIN_FRAME_RETRIES,
		       caps->min_frame_retries) ||
	    nla_put_s8(msg, NL802154_CAP_ATTR_MAX_FRAME_RETRIES,
		       caps->max_frame_retries) ||
	    nl802154_put_flags(msg, NL802154_CAP_ATTR_IFTYPES,
			       caps->iftypes) ||
	    nla_put_u32(msg, NL802154_CAP_ATTR_LBT, caps->lbt))
		return -ENOBUFS;

	nla_nest_end(msg, nl_caps);

	return 0;
}

static int nl802154_send_wpan_phy(struct cfg802154_registered_device *rdev,
				  enum nl802154_commands cmd,
				  struct sk_buff *msg, u32 portid, u32 seq,
				  int flags)
{
	struct nlattr *nl_cmds;
	void *hdr;
	int i;

	hdr = nl802154hdr_put(msg, portid, seq, flags, cmd);
	if (!hdr)
		return -ENOBUFS;

	if (nla_put_u32(msg, NL802154_ATTR_WPAN_PHY, rdev->wpan_phy_idx) ||
	    nla_put_string(msg, NL802154_ATTR_WPAN_PHY_NAME,
			   wpan_phy_name(&rdev->wpan_phy)) ||
	    nla_put_u32(msg, NL802154_ATTR_GENERATION,
			cfg802154_rdev_list_generation))
		goto nla_put_failure;

	if (cmd != NL802154_CMD_NEW_WPAN_PHY)
		goto finish;

	/* DUMP PHY PIB */

	/* current channel settings */
	if (nla_put_u8(msg, NL802154_ATTR_PAGE,
		       rdev->wpan_phy.current_page) ||
	    nla_put_u8(msg, NL802154_ATTR_CHANNEL,
		       rdev->wpan_phy.current_channel))
		goto nla_put_failure;

	/* TODO remove this behaviour, we still keep support it for a while
	 * so users can change the behaviour to the new one.
	 */
	if (nl802154_send_wpan_phy_channels(rdev, msg))
		goto nla_put_failure;

	/* cca mode */
	if (rdev->wpan_phy.flags & WPAN_PHY_FLAG_CCA_MODE) {
		if (nla_put_u32(msg, NL802154_ATTR_CCA_MODE,
				rdev->wpan_phy.cca.mode))
			goto nla_put_failure;

		if (rdev->wpan_phy.cca.mode == NL802154_CCA_ENERGY_CARRIER) {
			if (nla_put_u32(msg, NL802154_ATTR_CCA_OPT,
					rdev->wpan_phy.cca.opt))
				goto nla_put_failure;
		}
	}

	if (rdev->wpan_phy.flags & WPAN_PHY_FLAG_TXPOWER) {
		if (nla_put_s32(msg, NL802154_ATTR_TX_POWER,
				rdev->wpan_phy.transmit_power))
			goto nla_put_failure;
	}

	if (rdev->wpan_phy.flags & WPAN_PHY_FLAG_CCA_ED_LEVEL) {
		if (nla_put_s32(msg, NL802154_ATTR_CCA_ED_LEVEL,
				rdev->wpan_phy.cca_ed_level))
			goto nla_put_failure;
	}

	if (nl802154_put_capabilities(msg, rdev))
		goto nla_put_failure;

	nl_cmds = nla_nest_start(msg, NL802154_ATTR_SUPPORTED_COMMANDS);
	if (!nl_cmds)
		goto nla_put_failure;

	i = 0;
#define CMD(op, n)							\
	do {								\
		if (rdev->ops->op) {					\
			i++;						\
			if (nla_put_u32(msg, i, NL802154_CMD_ ## n))	\
				goto nla_put_failure;			\
		}							\
	} while (0)

	CMD(add_virtual_intf, NEW_INTERFACE);
	CMD(del_virtual_intf, DEL_INTERFACE);
	CMD(set_channel, SET_CHANNEL);
	CMD(set_pan_id, SET_PAN_ID);
	CMD(set_short_addr, SET_SHORT_ADDR);
	CMD(set_backoff_exponent, SET_BACKOFF_EXPONENT);
	CMD(set_max_csma_backoffs, SET_MAX_CSMA_BACKOFFS);
	CMD(set_max_frame_retries, SET_MAX_FRAME_RETRIES);
	CMD(set_lbt_mode, SET_LBT_MODE);
	CMD(ed_scan, ED_SCAN_REQ);

	if (rdev->wpan_phy.flags & WPAN_PHY_FLAG_TXPOWER)
		CMD(set_tx_power, SET_TX_POWER);

	if (rdev->wpan_phy.flags & WPAN_PHY_FLAG_CCA_ED_LEVEL)
		CMD(set_cca_ed_level, SET_CCA_ED_LEVEL);

	if (rdev->wpan_phy.flags & WPAN_PHY_FLAG_CCA_MODE)
		CMD(set_cca_mode, SET_CCA_MODE);

#undef CMD
	nla_nest_end(msg, nl_cmds);

finish:
	genlmsg_end(msg, hdr);
	return 0;

nla_put_failure:
	genlmsg_cancel(msg, hdr);
	return -EMSGSIZE;
}

struct nl802154_dump_wpan_phy_state {
	s64 filter_wpan_phy;
	long start;

};

static int nl802154_dump_wpan_phy_parse(struct sk_buff *skb,
					struct netlink_callback *cb,
					struct nl802154_dump_wpan_phy_state *state)
{
	struct nlattr **tb = nl802154_fam.attrbuf;
	int ret = nlmsg_parse(cb->nlh, GENL_HDRLEN + nl802154_fam.hdrsize,
			      tb, nl802154_fam.maxattr, nl802154_policy);

	/* TODO check if we can handle error here,
	 * we have no backward compatibility
	 */
	if (ret)
		return 0;

	if (tb[NL802154_ATTR_WPAN_PHY])
		state->filter_wpan_phy = nla_get_u32(tb[NL802154_ATTR_WPAN_PHY]);
	if (tb[NL802154_ATTR_WPAN_DEV])
		state->filter_wpan_phy = nla_get_u64(tb[NL802154_ATTR_WPAN_DEV]) >> 32;
	if (tb[NL802154_ATTR_IFINDEX]) {
		struct net_device *netdev;
		struct cfg802154_registered_device *rdev;
		int ifidx = nla_get_u32(tb[NL802154_ATTR_IFINDEX]);

		/* TODO netns */
		netdev = __dev_get_by_index(&init_net, ifidx);
		if (!netdev)
			return -ENODEV;
		if (netdev->ieee802154_ptr) {
			rdev = wpan_phy_to_rdev(
					netdev->ieee802154_ptr->wpan_phy);
			state->filter_wpan_phy = rdev->wpan_phy_idx;
		}
	}

	return 0;
}

static int
nl802154_dump_wpan_phy(struct sk_buff *skb, struct netlink_callback *cb)
{
	int idx = 0, ret;
	struct nl802154_dump_wpan_phy_state *state = (void *)cb->args[0];
	struct cfg802154_registered_device *rdev;

	rtnl_lock();
	if (!state) {
		state = kzalloc(sizeof(*state), GFP_KERNEL);
		if (!state) {
			rtnl_unlock();
			return -ENOMEM;
		}
		state->filter_wpan_phy = -1;
		ret = nl802154_dump_wpan_phy_parse(skb, cb, state);
		if (ret) {
			kfree(state);
			rtnl_unlock();
			return ret;
		}
		cb->args[0] = (long)state;
	}

	list_for_each_entry(rdev, &cfg802154_rdev_list, list) {
		/* TODO net ns compare */
		if (++idx <= state->start)
			continue;
		if (state->filter_wpan_phy != -1 &&
		    state->filter_wpan_phy != rdev->wpan_phy_idx)
			continue;
		/* attempt to fit multiple wpan_phy data chunks into the skb */
		ret = nl802154_send_wpan_phy(rdev,
					     NL802154_CMD_NEW_WPAN_PHY,
					     skb,
					     NETLINK_CB(cb->skb).portid,
					     cb->nlh->nlmsg_seq, NLM_F_MULTI);
		if (ret < 0) {
			if ((ret == -ENOBUFS || ret == -EMSGSIZE) &&
			    !skb->len && cb->min_dump_alloc < 4096) {
				cb->min_dump_alloc = 4096;
				rtnl_unlock();
				return 1;
			}
			idx--;
			break;
		}
		break;
	}
	rtnl_unlock();

	state->start = idx;

	return skb->len;
}

static int nl802154_dump_wpan_phy_done(struct netlink_callback *cb)
{
	kfree((void *)cb->args[0]);
	return 0;
}

static int nl802154_get_wpan_phy(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *msg;
	struct cfg802154_registered_device *rdev = info->user_ptr[0];

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	if (nl802154_send_wpan_phy(rdev, NL802154_CMD_NEW_WPAN_PHY, msg,
				   info->snd_portid, info->snd_seq, 0) < 0) {
		nlmsg_free(msg);
		return -ENOBUFS;
	}

	return genlmsg_reply(msg, info);
}

static inline u64 wpan_dev_id(struct wpan_dev *wpan_dev)
{
	return (u64)wpan_dev->identifier |
	       ((u64)wpan_phy_to_rdev(wpan_dev->wpan_phy)->wpan_phy_idx << 32);
}

static int
nl802154_send_iface(struct sk_buff *msg, u32 portid, u32 seq, int flags,
		    struct cfg802154_registered_device *rdev,
		    struct wpan_dev *wpan_dev)
{
	struct net_device *dev = wpan_dev->netdev;
	void *hdr;

	hdr = nl802154hdr_put(msg, portid, seq, flags,
			      NL802154_CMD_NEW_INTERFACE);
	if (!hdr)
		return -1;

	if (dev &&
	    (nla_put_u32(msg, NL802154_ATTR_IFINDEX, dev->ifindex) ||
	     nla_put_string(msg, NL802154_ATTR_IFNAME, dev->name)))
		goto nla_put_failure;

	if (nla_put_u32(msg, NL802154_ATTR_WPAN_PHY, rdev->wpan_phy_idx) ||
	    nla_put_u32(msg, NL802154_ATTR_IFTYPE, wpan_dev->iftype) ||
	    nla_put_u64(msg, NL802154_ATTR_WPAN_DEV, wpan_dev_id(wpan_dev)) ||
	    nla_put_u32(msg, NL802154_ATTR_GENERATION,
			rdev->devlist_generation ^
			(cfg802154_rdev_list_generation << 2)))
		goto nla_put_failure;

	/* address settings */
	if (nla_put_le64(msg, NL802154_ATTR_EXTENDED_ADDR,
			 wpan_dev->extended_addr) ||
	    nla_put_le16(msg, NL802154_ATTR_SHORT_ADDR,
			 wpan_dev->short_addr) ||
	    nla_put_le16(msg, NL802154_ATTR_PAN_ID, wpan_dev->pan_id))
		goto nla_put_failure;

	/* ARET handling */
	if (nla_put_s8(msg, NL802154_ATTR_MAX_FRAME_RETRIES,
		       wpan_dev->frame_retries) ||
	    nla_put_u8(msg, NL802154_ATTR_MAX_BE, wpan_dev->max_be) ||
	    nla_put_u8(msg, NL802154_ATTR_MAX_CSMA_BACKOFFS,
		       wpan_dev->csma_retries) ||
	    nla_put_u8(msg, NL802154_ATTR_MIN_BE, wpan_dev->min_be))
		goto nla_put_failure;

	/* listen before transmit */
	if (nla_put_u8(msg, NL802154_ATTR_LBT_MODE, wpan_dev->lbt))
		goto nla_put_failure;

	genlmsg_end(msg, hdr);
	return 0;

nla_put_failure:
	genlmsg_cancel(msg, hdr);
	return -EMSGSIZE;
}

static int
nl802154_dump_interface(struct sk_buff *skb, struct netlink_callback *cb)
{
	int wp_idx = 0;
	int if_idx = 0;
	int wp_start = cb->args[0];
	int if_start = cb->args[1];
	struct cfg802154_registered_device *rdev;
	struct wpan_dev *wpan_dev;

	rtnl_lock();
	list_for_each_entry(rdev, &cfg802154_rdev_list, list) {
		/* TODO netns compare */
		if (wp_idx < wp_start) {
			wp_idx++;
			continue;
		}
		if_idx = 0;

		list_for_each_entry(wpan_dev, &rdev->wpan_dev_list, list) {
			if (if_idx < if_start) {
				if_idx++;
				continue;
			}
			if (nl802154_send_iface(skb, NETLINK_CB(cb->skb).portid,
						cb->nlh->nlmsg_seq, NLM_F_MULTI,
						rdev, wpan_dev) < 0) {
				goto out;
			}
			if_idx++;
		}

		wp_idx++;
	}
out:
	rtnl_unlock();

	cb->args[0] = wp_idx;
	cb->args[1] = if_idx;

	return skb->len;
}

static int nl802154_get_interface(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *msg;
	struct cfg802154_registered_device *rdev = info->user_ptr[0];
	struct wpan_dev *wdev = info->user_ptr[1];

	msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	if (nl802154_send_iface(msg, info->snd_portid, info->snd_seq, 0,
				rdev, wdev) < 0) {
		nlmsg_free(msg);
		return -ENOBUFS;
	}

	return genlmsg_reply(msg, info);
}

static int nl802154_new_interface(struct sk_buff *skb, struct genl_info *info)
{
	struct cfg802154_registered_device *rdev = info->user_ptr[0];
	enum nl802154_iftype type = NL802154_IFTYPE_UNSPEC;
	__le64 extended_addr = cpu_to_le64(0x0000000000000000ULL);

	/* TODO avoid failing a new interface
	 * creation due to pending removal?
	 */

	if (!info->attrs[NL802154_ATTR_IFNAME])
		return -EINVAL;

	if (info->attrs[NL802154_ATTR_IFTYPE]) {
		type = nla_get_u32(info->attrs[NL802154_ATTR_IFTYPE]);
		if (type > NL802154_IFTYPE_MAX ||
		    !(rdev->wpan_phy.supported.iftypes & BIT(type)))
			return -EINVAL;
	}

	/* TODO add nla_get_le64 to netlink */
	if (info->attrs[NL802154_ATTR_EXTENDED_ADDR])
		extended_addr = (__force __le64)nla_get_u64(
				info->attrs[NL802154_ATTR_EXTENDED_ADDR]);

	if (!rdev->ops->add_virtual_intf)
		return -EOPNOTSUPP;

	return rdev_add_virtual_intf(rdev,
				     nla_data(info->attrs[NL802154_ATTR_IFNAME]),
				     NET_NAME_USER, type, extended_addr);
}

static int nl802154_del_interface(struct sk_buff *skb, struct genl_info *info)
{
	struct cfg802154_registered_device *rdev = info->user_ptr[0];
	struct wpan_dev *wpan_dev = info->user_ptr[1];

	if (!rdev->ops->del_virtual_intf)
		return -EOPNOTSUPP;

	/* If we remove a wpan device without a netdev then clear
	 * user_ptr[1] so that nl802154_post_doit won't dereference it
	 * to check if it needs to do dev_put(). Otherwise it crashes
	 * since the wpan_dev has been freed, unlike with a netdev where
	 * we need the dev_put() for the netdev to really be freed.
	 */
	if (!wpan_dev->netdev)
		info->user_ptr[1] = NULL;

	return rdev_del_virtual_intf(rdev, wpan_dev);
}

static int nl802154_set_channel(struct sk_buff *skb, struct genl_info *info)
{
	struct cfg802154_registered_device *rdev = info->user_ptr[0];
	u8 channel, page;

	if (!info->attrs[NL802154_ATTR_PAGE] ||
	    !info->attrs[NL802154_ATTR_CHANNEL])
		return -EINVAL;

	page = nla_get_u8(info->attrs[NL802154_ATTR_PAGE]);
	channel = nla_get_u8(info->attrs[NL802154_ATTR_CHANNEL]);

	/* check 802.15.4 constraints */
	if (page > IEEE802154_MAX_PAGE || channel > IEEE802154_MAX_CHANNEL ||
	    !(rdev->wpan_phy.supported.channels[page] & BIT(channel)))
		return -EINVAL;

	return rdev_set_channel(rdev, page, channel);
}

static int nl802154_set_cca_mode(struct sk_buff *skb, struct genl_info *info)
{
	struct cfg802154_registered_device *rdev = info->user_ptr[0];
	struct wpan_phy_cca cca;

	if (!(rdev->wpan_phy.flags & WPAN_PHY_FLAG_CCA_MODE))
		return -EOPNOTSUPP;

	if (!info->attrs[NL802154_ATTR_CCA_MODE])
		return -EINVAL;

	cca.mode = nla_get_u32(info->attrs[NL802154_ATTR_CCA_MODE]);
	/* checking 802.15.4 constraints */
	if (cca.mode < NL802154_CCA_ENERGY ||
	    cca.mode > NL802154_CCA_ATTR_MAX ||
	    !(rdev->wpan_phy.supported.cca_modes & BIT(cca.mode)))
		return -EINVAL;

	if (cca.mode == NL802154_CCA_ENERGY_CARRIER) {
		if (!info->attrs[NL802154_ATTR_CCA_OPT])
			return -EINVAL;

		cca.opt = nla_get_u32(info->attrs[NL802154_ATTR_CCA_OPT]);
		if (cca.opt > NL802154_CCA_OPT_ATTR_MAX ||
		    !(rdev->wpan_phy.supported.cca_opts & BIT(cca.opt)))
			return -EINVAL;
	}

	return rdev_set_cca_mode(rdev, &cca);
}

static int nl802154_set_cca_ed_level(struct sk_buff *skb, struct genl_info *info)
{
	struct cfg802154_registered_device *rdev = info->user_ptr[0];
	s32 ed_level;
	int i;

	if (!(rdev->wpan_phy.flags & WPAN_PHY_FLAG_CCA_ED_LEVEL))
		return -EOPNOTSUPP;

	if (!info->attrs[NL802154_ATTR_CCA_ED_LEVEL])
		return -EINVAL;

	ed_level = nla_get_s32(info->attrs[NL802154_ATTR_CCA_ED_LEVEL]);

	for (i = 0; i < rdev->wpan_phy.supported.cca_ed_levels_size; i++) {
		if (ed_level == rdev->wpan_phy.supported.cca_ed_levels[i])
			return rdev_set_cca_ed_level(rdev, ed_level);
	}

	return -EINVAL;
}

static int nl802154_set_tx_power(struct sk_buff *skb, struct genl_info *info)
{
	struct cfg802154_registered_device *rdev = info->user_ptr[0];
	s32 power;
	int i;

	if (!(rdev->wpan_phy.flags & WPAN_PHY_FLAG_TXPOWER))
		return -EOPNOTSUPP;

	if (!info->attrs[NL802154_ATTR_TX_POWER])
		return -EINVAL;

	power = nla_get_s32(info->attrs[NL802154_ATTR_TX_POWER]);

	for (i = 0; i < rdev->wpan_phy.supported.tx_powers_size; i++) {
		if (power == rdev->wpan_phy.supported.tx_powers[i])
			return rdev_set_tx_power(rdev, power);
	}

	return -EINVAL;
}

static int nl802154_set_pan_id(struct sk_buff *skb, struct genl_info *info)
{
	struct cfg802154_registered_device *rdev = info->user_ptr[0];
	struct net_device *dev = info->user_ptr[1];
	struct wpan_dev *wpan_dev = dev->ieee802154_ptr;
	__le16 pan_id;

	/* conflict here while tx/rx calls */
	if (netif_running(dev))
		return -EBUSY;

	/* don't change address fields on monitor */
	if (wpan_dev->iftype == NL802154_IFTYPE_MONITOR ||
	    !info->attrs[NL802154_ATTR_PAN_ID])
		return -EINVAL;

	pan_id = nla_get_le16(info->attrs[NL802154_ATTR_PAN_ID]);

	/* TODO
	 * I am not sure about to check here on broadcast pan_id.
	 * Broadcast is a valid setting, comment from 802.15.4:
	 * If this value is 0xffff, the device is not associated.
	 *
	 * This could useful to simple deassociate an device.
	 */
	if (pan_id == cpu_to_le16(IEEE802154_PAN_ID_BROADCAST))
		return -EINVAL;

	return rdev_set_pan_id(rdev, wpan_dev, pan_id);
}

static int nl802154_set_short_addr(struct sk_buff *skb, struct genl_info *info)
{
	struct cfg802154_registered_device *rdev = info->user_ptr[0];
	struct net_device *dev = info->user_ptr[1];
	struct wpan_dev *wpan_dev = dev->ieee802154_ptr;
	__le16 short_addr;

	/* conflict here while tx/rx calls */
	if (netif_running(dev))
		return -EBUSY;

	/* don't change address fields on monitor */
	if (wpan_dev->iftype == NL802154_IFTYPE_MONITOR ||
	    !info->attrs[NL802154_ATTR_SHORT_ADDR])
		return -EINVAL;

	short_addr = nla_get_le16(info->attrs[NL802154_ATTR_SHORT_ADDR]);

	/* TODO
	 * I am not sure about to check here on broadcast short_addr.
	 * Broadcast is a valid setting, comment from 802.15.4:
	 * A value of 0xfffe indicates that the device has
	 * associated but has not been allocated an address. A
	 * value of 0xffff indicates that the device does not
	 * have a short address.
	 *
	 * I think we should allow to set these settings but
	 * don't allow to allow socket communication with it.
	 */
	if (short_addr == cpu_to_le16(IEEE802154_ADDR_SHORT_UNSPEC) ||
	    short_addr == cpu_to_le16(IEEE802154_ADDR_SHORT_BROADCAST))
		return -EINVAL;

	return rdev_set_short_addr(rdev, wpan_dev, short_addr);
}

static int
nl802154_set_backoff_exponent(struct sk_buff *skb, struct genl_info *info)
{
	struct cfg802154_registered_device *rdev = info->user_ptr[0];
	struct net_device *dev = info->user_ptr[1];
	struct wpan_dev *wpan_dev = dev->ieee802154_ptr;
	u8 min_be, max_be;

	/* should be set on netif open inside phy settings */
	if (netif_running(dev))
		return -EBUSY;

	if (!info->attrs[NL802154_ATTR_MIN_BE] ||
	    !info->attrs[NL802154_ATTR_MAX_BE])
		return -EINVAL;

	min_be = nla_get_u8(info->attrs[NL802154_ATTR_MIN_BE]);
	max_be = nla_get_u8(info->attrs[NL802154_ATTR_MAX_BE]);

	/* check 802.15.4 constraints */
	if (min_be < rdev->wpan_phy.supported.min_minbe ||
	    min_be > rdev->wpan_phy.supported.max_minbe ||
	    max_be < rdev->wpan_phy.supported.min_maxbe ||
	    max_be > rdev->wpan_phy.supported.max_maxbe ||
	    min_be > max_be)
		return -EINVAL;

	return rdev_set_backoff_exponent(rdev, wpan_dev, min_be, max_be);
}

static int
nl802154_set_max_csma_backoffs(struct sk_buff *skb, struct genl_info *info)
{
	struct cfg802154_registered_device *rdev = info->user_ptr[0];
	struct net_device *dev = info->user_ptr[1];
	struct wpan_dev *wpan_dev = dev->ieee802154_ptr;
	u8 max_csma_backoffs;

	/* conflict here while other running iface settings */
	if (netif_running(dev))
		return -EBUSY;

	if (!info->attrs[NL802154_ATTR_MAX_CSMA_BACKOFFS])
		return -EINVAL;

	max_csma_backoffs = nla_get_u8(
			info->attrs[NL802154_ATTR_MAX_CSMA_BACKOFFS]);

	/* check 802.15.4 constraints */
	if (max_csma_backoffs < rdev->wpan_phy.supported.min_csma_backoffs ||
	    max_csma_backoffs > rdev->wpan_phy.supported.max_csma_backoffs)
		return -EINVAL;

	return rdev_set_max_csma_backoffs(rdev, wpan_dev, max_csma_backoffs);
}

static int
nl802154_set_max_frame_retries(struct sk_buff *skb, struct genl_info *info)
{
	struct cfg802154_registered_device *rdev = info->user_ptr[0];
	struct net_device *dev = info->user_ptr[1];
	struct wpan_dev *wpan_dev = dev->ieee802154_ptr;
	s8 max_frame_retries;

	if (netif_running(dev))
		return -EBUSY;

	if (!info->attrs[NL802154_ATTR_MAX_FRAME_RETRIES])
		return -EINVAL;

	max_frame_retries = nla_get_s8(
			info->attrs[NL802154_ATTR_MAX_FRAME_RETRIES]);

	/* check 802.15.4 constraints */
	if (max_frame_retries < rdev->wpan_phy.supported.min_frame_retries ||
	    max_frame_retries > rdev->wpan_phy.supported.max_frame_retries)
		return -EINVAL;

	return rdev_set_max_frame_retries(rdev, wpan_dev, max_frame_retries);
}

static int nl802154_set_lbt_mode(struct sk_buff *skb, struct genl_info *info)
{
	struct cfg802154_registered_device *rdev = info->user_ptr[0];
	struct net_device *dev = info->user_ptr[1];
	struct wpan_dev *wpan_dev = dev->ieee802154_ptr;
	bool mode;

	if (netif_running(dev))
		return -EBUSY;

	if (!info->attrs[NL802154_ATTR_LBT_MODE])
		return -EINVAL;

	mode = !!nla_get_u8(info->attrs[NL802154_ATTR_LBT_MODE]);
	if (!wpan_phy_supported_bool(mode, rdev->wpan_phy.supported.lbt))
		return -EINVAL;

	return rdev_set_lbt_mode(rdev, wpan_dev, mode);
}

static int nl802154_ed_scan_put_ed( struct sk_buff *reply, u8 result_list_size, u32 scan_channels, u8 *ed ) {
	int r;

	int i, j;
	struct nlattr *ed_list;
	ed_list = nla_nest_start( reply, NL802154_ATTR_SCAN_ENERGY_DETECT_LIST );
	if ( NULL == ed_list ) {
		r = -ENOBUFS;
		goto out;
	}
	for( i = 0, j = 0; i <= IEEE802154_MAX_CHANNEL && j <= result_list_size; i++ ) {
		if ( scan_channels & BIT( i ) ) {
			r = nla_put_u8( reply, NL802154_ATTR_SCAN_ENERGY_DETECT_LIST_ENTRY, ed[ j ] );
			if ( 0 != r ) {
				goto nla_put_failure;
			}
			j++;
		}
	}
	nla_nest_end( reply, ed_list );
	r = 0;
	goto out;

nla_put_failure:
	r = -ENOBUFS;
out:
	return r;
}

static void nl802154_ed_scan_cnf( struct work_struct *work ) {

	int r;
	const u8 scan_type = 0;

	u8 ed[ IEEE802154_MAX_CHANNEL + 1 ];

	struct work802154 *wrk;
	struct sk_buff *skb;
	struct genl_info *info;
	struct cfg802154_registered_device *rdev;
	struct device *dev;

	int i;

	u8 status;
	u8 channel_page;
	u32 scan_channels;
	u8 scan_duration;
	u32 unscanned_channels;
	u8 result_list_size;
	u8 detected_category;
	struct sk_buff *reply;
	void *hdr;

	wrk = container_of( to_delayed_work( work ), struct work802154, work );
	skb = wrk->skb;
	info = wrk->info;
	rdev = info->user_ptr[0];
	dev = &rdev->wpan_phy.dev;

	reply = nlmsg_new( NLMSG_DEFAULT_SIZE, GFP_KERNEL );
	if ( NULL == reply ) {
		r = -ENOMEM;
		dev_err( dev, "nlmsg_new failed (%d)\n", r );
		goto out;
	}

	hdr = nl802154hdr_put( reply, info->snd_portid, info->snd_seq, 0, NL802154_CMD_ED_SCAN_CNF );
	if ( NULL == hdr ) {
		r = -ENOBUFS;
		goto free_reply;
	}

	status = IEEE802154_SUCCESS;
	unscanned_channels = 0;
	detected_category = 2; // ed_scan

	channel_page = wrk->cmd_stuff.ed_scan.channel_page;
	scan_channels = wrk->cmd_stuff.ed_scan.scan_channels;
	scan_duration = wrk->cmd_stuff.ed_scan.scan_duration;

	for( result_list_size = 0, i = 0; i < 8 * sizeof( scan_channels ) && i <= IEEE802154_MAX_CHANNEL; i++ ) {
		result_list_size += !!( scan_channels & (1 << i) );
	}

	r = rdev_ed_scan(rdev, NULL, channel_page, scan_channels, ed, result_list_size, scan_duration );
	if ( r < 0 ) {
		dev_err( dev, "rdev_ed_scan failed (%d)\n", r );
		goto free_reply;
	}

	r =
		nla_put_u8( reply, NL802154_ATTR_SCAN_STATUS, status ) ||
		nla_put_u8( reply, NL802154_ATTR_SCAN_TYPE, scan_type ) ||
		nla_put_u8( reply, NL802154_ATTR_PAGE, channel_page ) ||
		nla_put_u32( reply, NL802154_ATTR_SUPPORTED_CHANNEL, unscanned_channels ) ||
		nla_put_u8( reply, NL802154_ATTR_SCAN_RESULT_LIST_SIZE, result_list_size ) ||
		nl802154_ed_scan_put_ed( reply, result_list_size, scan_channels, ed ) ||
		nla_put_u8( reply, NL802154_ATTR_SCAN_DETECTED_CATEGORY, detected_category );
	if ( 0 != r ) {
		dev_err( dev, "nla_put_failure (%d)\n", r );
		goto nla_put_failure;
	}

	genlmsg_end( reply, hdr );

	r = genlmsg_reply( reply, info );
	goto out;

nla_put_failure:
free_reply:
	nlmsg_free( reply );
out:
	complete( &wrk->completion );
	kfree( wrk );
	return;
}

static int nl802154_ed_scan_req( struct sk_buff *skb, struct genl_info *info )
{
	int r;

	u8 scan_type;
	u32 scan_channels;
	u8 scan_duration;
	u8 channel_page;

	struct cfg802154_registered_device *rdev;
	struct work802154 *wrk;
	struct device *dev;

	rdev = info->user_ptr[0];
	dev = &rdev->wpan_phy.dev;

	if ( ! (
		info->attrs[ NL802154_ATTR_SCAN_TYPE ] &&
		info->attrs[ NL802154_ATTR_SUPPORTED_CHANNEL ] &&
		info->attrs[ NL802154_ATTR_SCAN_DURATION ] &&
		info->attrs[ NL802154_ATTR_PAGE ]
	) ) {
		r = -EINVAL;
		goto out;
	}

	scan_type = nla_get_u8( info->attrs[ NL802154_ATTR_SCAN_TYPE ] );
	scan_channels = nla_get_u32( info->attrs[ NL802154_ATTR_SUPPORTED_CHANNEL ] );
	scan_duration = nla_get_u8( info->attrs[ NL802154_ATTR_SCAN_DURATION ] );
	channel_page = nla_get_u8( info->attrs[ NL802154_ATTR_PAGE ] );

	if ( channel_page > IEEE802154_MAX_PAGE ) {
		dev_err( dev, "invalid channel_page %u\n", channel_page );
		r = -EINVAL;
		goto out;
	}

	if ( scan_channels & ~rdev->wpan_phy.supported.channels[ channel_page ] ) {
		dev_err( dev, "invalid scan_channels %u\n", scan_channels );
		r = -EINVAL;
		goto out;
	}

	wrk = kzalloc( sizeof( *wrk ), GFP_KERNEL );
	if ( NULL == wrk ) {
		r = -ENOMEM;
		goto out;
	}

	wrk->cmd = NL802154_CMD_ED_SCAN_REQ;
	wrk->skb = skb;
	wrk->info = info;
	wrk->cmd_stuff.ed_scan.channel_page = channel_page;
	wrk->cmd_stuff.ed_scan.scan_channels = scan_channels;
	wrk->cmd_stuff.ed_scan.scan_duration = scan_duration;

	init_completion( &wrk->completion );
	INIT_DELAYED_WORK( &wrk->work, nl802154_ed_scan_cnf );
	r = schedule_delayed_work( &wrk->work, 0 ) ? 0 : -EALREADY;
	if ( 0 != r ) {
		dev_err( dev, "schedule_delayed_work failed (%d)\n", r );
		goto free_wrk;
	}

	wait_for_completion( &wrk->completion );

	r = 0;
	goto out;

free_wrk:
	kfree( wrk );

out:
	return r;
}

enum {
	MAC_ERR_SUCCESS,
	MAC_ERR_PAN_AT_CAPACITY,
	MAC_ERR_ACCESS_DENIED,
	MAC_ERR_RESERVED = 0x7f,
	MAC_ERR_CHANNEL_ACCESS_FAILURE,
	MAC_ERR_NO_ACK,
	MAC_ERR_NO_DATA,
	MAC_ERR_COUNTER_ERROR,
	MAC_ERR_FRAME_TOO_LONG,
	MAC_ERR_IMPROPER_KEY_TYPE,
	MAC_ERR_IMPROPER_SECURITY_LEVEL,
	MAC_ERR_SECURITY_ERROR,
	MAC_ERR_UNAVAILABLE_KEY,
	MAC_ERR_UNSUPPORTED_LEGACY,
	MAC_ERR_UNSUPPORTED_SECURITY,
	MAC_ERR_INVALID_PARAMETER,
};

static void nl802154_assoc_cnf( struct genl_info *info, u16 assoc_short_address, u8 status )
{
	int r;
	struct cfg802154_registered_device *rdev;
	struct wpan_dev *wpan_dev;
	struct net_device *netdev;

	struct sk_buff *reply;
	void *hdr;

	rdev = info->user_ptr[0];
	netdev = info->user_ptr[1];
	wpan_dev = netdev->ieee802154_ptr;

	r = rdev_set_short_addr( rdev, wpan_dev, assoc_short_address );
	if ( 0 != r ) {
		dev_err( &netdev->dev, "set short addr failure (%d)\n", r );
		goto out;
    }

	reply = nlmsg_new( NLMSG_DEFAULT_SIZE, GFP_KERNEL );
    if ( NULL == reply ) {
        r = -ENOMEM;
        dev_err( &netdev->dev, "nlmsg_new failed (%d)\n", r );
        goto out;
    }

    hdr = nl802154hdr_put( reply, info->snd_portid, info->snd_seq, 0, NL802154_CMD_ASSOC_CNF );
    if ( NULL == hdr ) {
        r = -ENOBUFS;
        goto free_reply;
    }

    r =
        nla_put_u16( reply, NL802154_ATTR_SHORT_ADDR, assoc_short_address ) ||
        nla_put_u8( reply, NL802154_ATTR_ASSOC_STATUS, status );
    if ( 0 != r ) {
        dev_err( &netdev->dev, "nla_put_failure (%d)\n", r );
        goto nla_put_failure;
    }

    genlmsg_end( reply, hdr );

    r = genlmsg_reply( reply, info );
    goto out;

nla_put_failure:
free_reply:
    nlmsg_free( reply );
out:
    return;
}

static void nl802154_assoc_req_complete( struct sk_buff *skb_in, void *arg ) {

	struct work_struct *work = (struct work_struct *)arg;
	struct work802154 *wrk = container_of( to_delayed_work( work ), struct work802154, work );

	struct genl_info *info = wrk->info;

	struct cfg802154_registered_device *rdev = info->user_ptr[0];
	struct net_device *dev = info->user_ptr[1];
	struct wpan_dev *wpan_dev = dev->ieee802154_ptr;

	u16 short_addr = *( (u16 *) &skb_in->data[1] );
	u8 status = skb_in->data[3];

	cancel_delayed_work( &wrk->work );

	rdev_deregister_assoc_req_listener( rdev, wpan_dev, nl802154_assoc_req_complete, work );

	nl802154_assoc_cnf( info, short_addr, status );

	complete( &wrk->completion );
	kfree( wrk );
}

static void nl802154_assoc_req_timeout( struct work_struct *work ) {

	static const u16 assoc_short_address = IEEE802154_ADDR_BROADCAST;
	static const u8 status = MAC_ERR_NO_DATA;

	struct work802154 *wrk = container_of( to_delayed_work( work ), struct work802154, work );

	struct genl_info *info = wrk->info;
	struct cfg802154_registered_device *rdev = info->user_ptr[0];

	nl802154_assoc_cnf( info, assoc_short_address, status );

    rdev_deregister_assoc_req_listener( rdev, NULL, nl802154_assoc_req_complete, work );

	complete( &wrk->completion );
	kfree( wrk );
}

static int
nl802154_assoc_send_empty_data_req(struct wpan_phy *wpan_phy, struct wpan_dev *wpan_dev,
		u8 addr_mode, u16 coord_pan_id, u64 coord_addr)
{

	int r = 0;
	struct sk_buff *skb;
	struct ieee802154_mac_cb *cb;
	int hlen, tlen, size;
	struct ieee802154_addr dst_addr, source_addr;
	unsigned char *data;
	u64 src_addr;

	src_addr = wpan_dev->extended_addr;

	memset( &source_addr, 0, sizeof( source_addr ) );
	memset( &dst_addr, 0, sizeof( dst_addr ) );

	hlen = 2 + 2 + 1 + 8 + 2; // Packet Length + Frame Control + Sequence Number + Extended Source Addr for Association Request + Destination PAN ID
	hlen += IEEE802154_ADDR_LONG == addr_mode ? 8 : 2; // Extended or Short Destination address
	tlen = wpan_dev->netdev->needed_tailroom;
	size = 1; //Todo: Replace magic number. Comes from ieee std 802154 "Association Request Frame Format" with a define

	skb = alloc_skb( hlen + tlen + size, GFP_KERNEL );
	if (!skb){
		goto error;
	}

	skb_reserve(skb, hlen);

	skb_reset_network_header(skb);

	data = skb_put(skb, size);

	source_addr.mode = IEEE802154_ADDR_LONG;
	source_addr.extended_addr = src_addr;

	dst_addr.mode = addr_mode;
	dst_addr.pan_id = coord_pan_id;

	if ( IEEE802154_ADDR_SHORT == addr_mode ){
		dst_addr.short_addr = (__le16)coord_addr;
	} else {
		dst_addr.extended_addr = coord_addr;
	}

	cb = mac_cb_init(skb);
	cb->type = IEEE802154_FC_TYPE_MAC_CMD;
	cb->ackreq = true;

	cb->secen = false;
	cb->secen_override = false;
	cb->seclevel = 0;

	cb->source = source_addr;
	cb->dest = dst_addr;

	cb->intra_pan = true;

	r = wpan_dev->netdev->header_ops->create( skb, wpan_dev->netdev, ETH_P_IEEE802154, &dst_addr, &source_addr, hlen + tlen + size);

	//Add the mac header to the data
	memcpy( data, cb, size );
	data[0] = IEEE802154_CMD_DATA_REQ;

	skb->dev = wpan_dev->netdev;
	skb->protocol = htons(ETH_P_IEEE802154);

	r = ieee802154_subif_start_xmit( skb, wpan_dev->netdev );
	if( 0 == r) {
		goto out;
	}

error:
	kfree_skb(skb);
out:
	return r;
}

static int
nl802154_assoc_send_assoc_req(struct wpan_phy *wpan_phy, struct wpan_dev *wpan_dev,
		u8 addr_mode, u16 coord_pan_id, u64 coord_addr,
		u8 capability_information ){

	int r;

	struct sk_buff *skb;
	struct ieee802154_mac_cb *cb;
	int hlen, tlen, size;
	struct ieee802154_addr dst_addr, source_addr;
	unsigned char *data;
	u64 src_addr;

	struct net_device *netdev;
	struct device *logdev;

	netdev = wpan_dev->netdev;
	logdev = &netdev->dev;

	src_addr = wpan_dev->extended_addr;

	memset( &source_addr, 0, sizeof( source_addr ) );
	memset( &dst_addr, 0, sizeof( dst_addr ) );

	//Create beacon frame / payload
	hlen = 2 + 2 + 1 + 8 + 2 + 2; // Packet Length + Frame Control + Sequence Number + Extended Source Addr for Association Request + Source PAN ID + Dest PAN ID
	hlen += IEEE802154_ADDR_LONG == addr_mode ? 8 : 2; // Extended or Short Destination address
	tlen = wpan_dev->netdev->needed_tailroom;
	size = 2; //Todo: Replace magic number. Comes from ieee std 802154 "Association Request Frame Format" with a define

	dev_dbg( logdev, "The skb lengths used are hlen: %d, tlen %d, and size %d\n", hlen, tlen, size);
	dev_dbg( logdev, "Address of the netdev device structure: %p\n", wpan_dev->netdev );
	//dev_dbg( logdev, "Address of ieee802154_local * local from wpan_phy_priv: %p\n", local );

	skb = alloc_skb( hlen + tlen + size, GFP_KERNEL );
	if (!skb){
		r = -ENOMEM;
		goto error;
	}

	skb_reserve(skb, hlen);

	skb_reset_network_header(skb);

	data = skb_put(skb, size);

	source_addr.mode = IEEE802154_ADDR_LONG;
	source_addr.pan_id = IEEE802154_PANID_BROADCAST;
	source_addr.extended_addr = src_addr;

	dst_addr.mode = addr_mode;
	dst_addr.pan_id = coord_pan_id;

	if ( IEEE802154_ADDR_SHORT == addr_mode ){
		dst_addr.short_addr = (__le16)coord_addr;
	} else {
		dst_addr.extended_addr = coord_addr;
	}

	cb = mac_cb_init(skb);
	cb->type = IEEE802154_FC_TYPE_MAC_CMD;
	cb->ackreq = true;

	cb->secen = false;
	cb->secen_override = false;
	cb->seclevel = 0;

	cb->source = source_addr;
	cb->dest = dst_addr;

	//No security fields in yet.

	dev_dbg( logdev, "DSN value in wpan_dev: %p\n", &wpan_dev->dsn);

	dev_dbg( logdev, "Dest addr: 0x%04x\n", dst_addr.short_addr );
	dev_dbg( logdev, "Dest addr long: 0x%016" PRIx64 "\n", dst_addr.extended_addr );
	dev_dbg( logdev, "Src addr: 0x%04x\n", source_addr.short_addr );
	dev_dbg( logdev, "Src addr long: 0x%016" PRIx64 "\n", source_addr.extended_addr );

	netdev->header_ops->create( skb, netdev, ETH_P_IEEE802154, &dst_addr, &source_addr, hlen + tlen + size);

	//Add the mac header to the data
	memcpy( data, cb, size );
	data[0] = IEEE802154_CMD_ASSOCIATION_REQ;
	data[1] = capability_information;

	skb->dev = wpan_dev->netdev;
	skb->protocol = htons(ETH_P_IEEE802154);

	dev_dbg( logdev, "Data bytes sent out %x, %x\n", data[0], data[1]);

	r = ieee802154_subif_start_xmit( skb, wpan_dev->netdev );
	if( 0 != r) {
		goto error;
	}

	goto out;

error:
	kfree_skb(skb);
out:
	return r;
}

static int nl802154_assoc_req( struct sk_buff *skb, struct genl_info *info )
{
	int r;
	u8 channel_number;
	u8 channel_page;
	u8 coord_addr_mode;
	u16 coord_pan_id;
	u64 coord_address;
	u8 capability_information;
	char coord_addr_str[] = "0x0011223344556677";
//	XXX: TODO
//	u32 security_level;
//	u32 key_id_mode;
//	u64 key_source;
//	u32 key_index;
	u16 timeout_ms;

	struct cfg802154_registered_device *rdev;
	struct work802154 *wrk;
	struct net_device *netdev;
	struct wpan_dev *wpan_dev;
	struct device *logdev;

	rdev = info->user_ptr[0];
	netdev = info->user_ptr[1];
	wpan_dev = netdev->ieee802154_ptr;

	if ( wpan_dev->netdev != netdev ) {
		printk( KERN_INFO "netdev (%p) != wpan_dev->netdev (%p)\n", netdev, wpan_dev->netdev );
	}

	logdev = &netdev->dev;

	if ( ! (
		info->attrs[ NL802154_ATTR_CHANNEL ] &&
		info->attrs[ NL802154_ATTR_PAGE ] &&
		info->attrs[ NL802154_ATTR_ADDR_MODE ] &&
		info->attrs[ NL802154_ATTR_PAN_ID ] &&
		(
			info->attrs[ NL802154_ATTR_SHORT_ADDR ] ||
			info->attrs[ NL802154_ATTR_EXTENDED_ADDR ]
		) &&
		info->attrs[ NL802154_ATTR_ASSOC_CAP_INFO ] &&
		info->attrs[ NL802154_ATTR_ASSOC_TIMEOUT_MS ]
	) ) {
		dev_err( logdev, "invalid arguments\n" );
		r = -EINVAL;
		goto out;
	}

	channel_number = nla_get_u8( info->attrs[ NL802154_ATTR_CHANNEL ] );
	channel_page = nla_get_u8( info->attrs[ NL802154_ATTR_PAGE ] );
	coord_addr_mode = nla_get_u8( info->attrs[ NL802154_ATTR_ADDR_MODE ] );
	coord_pan_id = nla_get_u16( info->attrs[ NL802154_ATTR_PAN_ID ] );
	timeout_ms = nla_get_u16( info->attrs[ NL802154_ATTR_ASSOC_TIMEOUT_MS ]);

	switch( coord_addr_mode ) {
	case IEEE802154_ADDR_SHORT:
		if ( info->attrs[ NL802154_ATTR_SHORT_ADDR ] ) {
			coord_address = nla_get_u16( info->attrs[ NL802154_ATTR_SHORT_ADDR ] );
			snprintf( coord_addr_str, sizeof(coord_addr_str), "0x%04x", (u16)coord_address );
			break;
		}
		/* no break */
	case IEEE802154_ADDR_LONG:
		if ( info->attrs[ NL802154_ATTR_EXTENDED_ADDR ] ) {
			coord_address = nla_get_u64( info->attrs[ NL802154_ATTR_EXTENDED_ADDR ] );
			snprintf( coord_addr_str, sizeof(coord_addr_str), "0x%016" PRIx64, (u64)coord_address );
			break;
		}
		/* no break */
	default:
		dev_err( logdev, "invalid address / mode combination\n" );
		r = -EINVAL;
		goto out;
	}

	capability_information = nla_get_u8( info->attrs[ NL802154_ATTR_ASSOC_CAP_INFO ] );

	if ( channel_page > IEEE802154_MAX_PAGE ) {
		dev_err( logdev, "invalid channel_page %u\n", channel_page );
		r = -EINVAL;
		goto out;
	}

	if ( BIT( channel_number ) & ~rdev->wpan_phy.supported.channels[ channel_page ] ) {
		dev_err( logdev, "invalid channel_number %u\n", channel_number );
		r = -EINVAL;
		goto out;
	}

	wrk = kzalloc( sizeof( *wrk ), GFP_KERNEL );
	if ( NULL == wrk ) {
		r = -ENOMEM;
		goto out;
	}

	wrk->skb = skb;
	wrk->info = info;

	r = rdev_set_channel(rdev, channel_page, channel_number);
	if ( 0 != r ) {
		dev_err( logdev, "rdev_set_channel failed (%d)\n", r );
		goto free_wrk;
	}

	rdev_set_pan_id(rdev, wpan_dev, coord_pan_id);
	if ( 0 != r ) {
		dev_err( logdev, "rdev_set_pan_id failed (%d)\n", r );
		goto free_wrk;
	}

	r = rdev_register_assoc_req_listener( rdev, NULL, nl802154_assoc_req_complete, &wrk->work.work );
	if ( 0 != r ) {
		dev_err( logdev, "register assoc_req listener failed (%d)\n", r );
		goto free_wrk;
	}

	dev_dbg( logdev, "channel_number: %u, channel_page: %u, coord_addr_mode: %u, coord_pan_id: 0x%04x, coord_address: %s, capability_information: 0x%02x, timeout_ms: %u\n",
		channel_number, channel_page, coord_addr_mode, coord_pan_id, coord_addr_str, capability_information, timeout_ms );

	r = nl802154_assoc_send_assoc_req( &rdev->wpan_phy, wpan_dev, coord_addr_mode, coord_pan_id, coord_address, capability_information );
	if ( 0 != r ) {
		dev_err( logdev, "send assoc_req failed (%d)\n", r );
		goto dereg_listener;
	}

	// XXX: <BEGIN SNIP>
	// XXX: FIXME: This needs to be handled in the callback function via state machine, not here
	msleep(50);

	// XXX: define this function statically in this file.
	// XXX: eventually, it should be handled from userspace
	r = nl802154_assoc_send_empty_data_req( &rdev->wpan_phy, wpan_dev, coord_addr_mode, coord_pan_id, coord_address );
	if ( 0 != r ) {
		dev_err( logdev, "ack assoc_req failed (%d)\n", r );
		goto dereg_listener;
	}
	// XXX: <END SNIP>

	init_completion( &wrk->completion );
	INIT_DELAYED_WORK( &wrk->work, nl802154_assoc_req_timeout );
	r = schedule_delayed_work( &wrk->work, msecs_to_jiffies( timeout_ms ) ) ? 0 : -EALREADY;
	if ( 0 != r ) {
		dev_err( logdev, "schedule_delayed_work failed (%d)\n", r );
		goto free_wrk;
	}

	wait_for_completion( &wrk->completion );

	r = 0;
	goto out;

free_wrk:
	kfree( wrk );

dereg_listener:
	rdev_deregister_assoc_req_listener( rdev, NULL, nl802154_assoc_req_complete, &wrk->work.work );

out:
	return r;
}

static int nl802154_assoc_rsp( struct sk_buff *skb, struct genl_info *info )
{
	int r;
	r = -ENOSYS;
	return r;
}

static int nl802154_beacon_ind( struct genl_info *info, struct ieee802154_beacon_indication *ind )
{
	int ret = 0;

	int i;
	void *hdr;
	struct sk_buff *msg;
	struct nlattr *nl_pan_desc;
	struct nlattr *nl_sdu;
	struct cfg802154_registered_device *rdev = info->user_ptr[0];

	dev_dbg( &rdev->wpan_phy.dev, "Inside %s\n", __FUNCTION__);

	msg = genlmsg_new( NLMSG_DEFAULT_SIZE, GFP_KERNEL );
	if ( NULL == msg ) {
		ret = -ENOMEM;
		goto out;
	}

	hdr = nl802154hdr_put( msg, info->snd_portid, info->snd_seq, 0, NL802154_CMD_BEACON_NOTIFY_IND );
	if ( NULL == hdr ) {
		ret = -ENOBUFS;
		goto free_reply;
	}

	ret = nla_put_u8( msg, NL802154_ATTR_BEACON_SEQUENCE_NUMBER, ind->bsn );
	if ( 0 != ret ) {
		goto nla_put_failure;
	}

	nl_pan_desc = nla_nest_start( msg, NL802154_ATTR_PAN_DESCRIPTOR );
	if (nla_put_u8 ( msg, NL802154_ATTR_PAN_DESC_SRC_ADDR_MODE, ind->pan_desc.src_addr_mode ) ||
	    nla_put_u16( msg, NL802154_ATTR_PAN_DESC_SRC_PAN_ID, ind->pan_desc.src_pan_id) ||
	    nla_put_u32( msg, NL802154_ATTR_PAN_DESC_SRC_ADDR, ind->pan_desc.src_addr) ||
	    nla_put_u8 ( msg, NL802154_ATTR_PAN_DESC_CHANNEL_NUM, ind->pan_desc.channel_num) ||
	    nla_put_u8 ( msg, NL802154_ATTR_PAN_DESC_CHANNEL_PAGE, ind->pan_desc.channel_page) ||
	    nla_put_u8 ( msg, NL802154_ATTR_PAN_DESC_SUPERFRAME_SPEC, ind->pan_desc.superframe_spec) ||
	    nla_put_u32( msg, NL802154_ATTR_PAN_DESC_GTS_PERMIT, ind->pan_desc.gts_permit) ||
	    nla_put_u8 ( msg, NL802154_ATTR_PAN_DESC_LQI, ind->pan_desc.lqi) ||
	    nla_put_u32( msg, NL802154_ATTR_PAN_DESC_TIME_STAMP, ind->pan_desc.time_stamp) ||
	    nla_put_u8 ( msg, NL802154_ATTR_PAN_DESC_SEC_STATUS, ind->pan_desc.sec_status) ||
	    nla_put_u8 ( msg, NL802154_ATTR_PAN_DESC_SEC_LEVEL, ind->pan_desc.sec_level) ||
	    nla_put_u8 ( msg, NL802154_ATTR_PAN_DESC_KEY_ID_MODE, ind->pan_desc.key_id_mode) ||
	    nla_put_u8 ( msg, NL802154_ATTR_PAN_DESC_KEY_SRC, ind->pan_desc.key_src) ||
	    nla_put_u8 ( msg, NL802154_ATTR_PAN_DESC_KEY_INDEX, ind->pan_desc.key_index)) {
		ret = -ENOBUFS;
		goto free_reply;
	}
	nla_nest_end( msg, nl_pan_desc );

	ret = nla_put_u8( msg, NL802154_ATTR_PEND_ADDR_SPEC, ind->pend_addr_spec );
	if ( 0 != ret ) {
		goto nla_put_failure;
	}

	ret = nla_put_u32( msg, NL802154_ATTR_SDU_LENGTH, ind->sdu_len);
	if ( 0 != ret ) {
		goto nla_put_failure;
	}

	nl_sdu = nla_nest_start( msg, NL802154_ATTR_SDU );
	for (i = 0; i <= ind->sdu_len; i++) {
		ret = nla_put_u8(msg, NL802154_ATTR_SDU_ENTRY, ind->sdu[i]);
	    if ( 0 != ret ) {
		goto nla_put_failure;
	    }
	}
	nla_nest_end( msg, nl_sdu );

	genlmsg_end( msg, hdr );

	ret = genlmsg_reply( msg, info );
	goto out;

nla_put_failure:
free_reply:
	nlmsg_free( msg );

out:
	return ret;

}

static void nl802154_beacon_ind_complete( struct sk_buff *skb_in, const struct ieee802154_hdr *hdr, void *arg )
{
	struct work_struct *work = (struct work_struct *)arg;
	struct work802154 *wrk = container_of( to_delayed_work( work ), struct work802154, work );

	struct genl_info *info = wrk->info;

	struct cfg802154_registered_device *rdev = info->user_ptr[0];
	struct wpan_dev *wpan_dev = info->user_ptr[1];

	/* Grab beacon indication data */
	struct ieee802154_beacon_indication ind;
	memset(&ind, 0, sizeof(ind));

	ind.bsn = hdr->seq;
	ind.pan_desc.src_addr        = mac_cb(skb_in)->source.short_addr;
	ind.pan_desc.src_pan_id      = mac_cb(skb_in)->source.pan_id;
	ind.pan_desc.channel_num     = rdev->wpan_phy.current_channel;
	ind.pan_desc.channel_page    = rdev->wpan_phy.current_page;
	ind.pan_desc.superframe_spec = 0;
	ind.pan_desc.gts_permit      = 0;
	ind.pan_desc.lqi             = mac_cb(skb_in)->lqi;
	ind.pan_desc.time_stamp      = 0;
	ind.pan_desc.sec_status      = 0;
	ind.pan_desc.sec_level       = mac_cb(skb_in)->seclevel;
	ind.pan_desc.key_id_mode     = hdr->sec.key_id_mode;
	ind.pan_desc.key_src         = 0;
	ind.pan_desc.key_index       = hdr->sec.key_id;
	ind.sdu_len = skb_in->len - skb_in->data_len;
	memcpy(&ind.sdu, skb_in->data, ind.sdu_len);

	cancel_delayed_work( &wrk->work );

	rdev_deregister_beacon_listener( rdev, wpan_dev, nl802154_beacon_ind_complete, work );

	nl802154_beacon_ind( info, &ind );

	complete( &wrk->completion );
	kfree( wrk );
}

static void nl802154_beacon_ind_timeout( struct work_struct *work )
{
        struct ieee802154_beacon_indication ind = { 0 };

	struct work802154 *wrk = container_of( to_delayed_work( work ), struct work802154, work );

	struct genl_info *info = wrk->info;
	struct cfg802154_registered_device *rdev = info->user_ptr[0];

	nl802154_beacon_ind( info, &ind );

	rdev_deregister_beacon_listener( rdev, NULL, nl802154_beacon_ind_complete, work );

	complete( &wrk->completion );
	kfree( wrk );
}

static int nl802154_get_beacon_indication( struct sk_buff *skb, struct genl_info *info )
{
	int r = 0;

	u16 timeout_ms;
	struct cfg802154_registered_device *rdev;
	struct work802154 *wrk;
	struct wpan_dev *wpan_dev;
	struct net_device *dev;

	rdev = info->user_ptr[0];
	wpan_dev = (struct wpan_dev *) &rdev->wpan_phy.dev;
	dev = (struct net_device *) &wpan_dev->netdev;

	dev_dbg( &dev->dev, "Inside %s\n", __FUNCTION__);

	if ( ! ( info->attrs[ NL802154_ATTR_BEACON_INDICATION_TIMEOUT ] ) ) {
		r = -EINVAL;
		goto out;
	}

	wrk = kzalloc( sizeof( *wrk ), GFP_KERNEL );
	if ( NULL == wrk ) {
		r = -ENOMEM;
		goto out;
	}

	timeout_ms = nla_get_u16( info->attrs[ NL802154_ATTR_BEACON_INDICATION_TIMEOUT ] );
	wrk->info = info;

	// Enable reception of beacon packets, and sending out netlink response
	r = rdev_register_beacon_listener( rdev, wpan_dev, nl802154_beacon_ind_complete, &wrk->work.work );
	if ( 0 != r ) {
		dev_err( &dev->dev, "rdev_register_beacon_ind_listener failed (%d)\n", r );
		goto free_wrk;
	}

	init_completion( &wrk->completion );
	INIT_DELAYED_WORK( &wrk->work, nl802154_beacon_ind_timeout );
	r = schedule_delayed_work( &wrk->work, msecs_to_jiffies( timeout_ms ) ) ? 0 : -EALREADY;
	if ( 0 != r ) {
		dev_err( &dev->dev, "nl802154_add_work failed (%d)\n", r );
		goto free_wrk;
	}

	// Wait for work function to signal completion after timeout_ms.  This should be enough
	// time for us to receive a beacon frame and send the indication back to user space
	// before returning (and closing the netlink socket).
	// Data is queued up and sent out once this doit() function returns.

	wait_for_completion( &wrk->completion );

	r = 0;
	goto out;

free_wrk:
    kfree( wrk );
out:
	return r;
}

static inline bool is_extended_address( u64 addr ) {
	static const u64 mask = ~((1 << 16) - 1);
	return mask & addr;
}

static void nl802154_disassoc_cnf( struct sk_buff *skb, struct genl_info *info, u8 status, u16 device_panid, u64 device_address ) {

	int r;

	struct cfg802154_registered_device *rdev = info->user_ptr[0];
	struct net_device *dev = info->user_ptr[1];
	struct wpan_dev *wpan_dev = dev->ieee802154_ptr;

	char device_addr_buf[32];
	struct sk_buff *reply;
	void *hdr;

	if ( is_extended_address( device_address ) ) {
		snprintf( device_addr_buf, sizeof( device_addr_buf ), "0x%0" PRIx64, device_address );
	} else {
		snprintf( device_addr_buf, sizeof( device_addr_buf ), "0x%04x", (u16)device_address );
	}

	reply = nlmsg_new( NLMSG_DEFAULT_SIZE, GFP_KERNEL );
	if ( NULL == reply ) {
		r = -ENOMEM;
		dev_err( &dev->dev, "nlmsg_new failed (%d)\n", r );
		goto out;
	}

	hdr = nl802154hdr_put( reply, info->snd_portid, info->snd_seq, 0, NL802154_CMD_DISASSOC_CNF );
	if ( NULL == hdr ) {
		r = -ENOBUFS;
		goto free_reply;
	}

	r =
		nla_put_u8( reply, NL802154_ATTR_DISASSOC_STATUS, status ) ||
		nla_put_u16( reply, NL802154_ATTR_ADDR_MODE, is_extended_address( device_address ) ? IEEE802154_ADDR_LONG : IEEE802154_ADDR_SHORT ) ||
		nla_put_u16( reply, NL802154_ATTR_PAN_ID, device_panid ) ||
		(
			( is_extended_address( device_address ) && nla_put_u64( reply, NL802154_ATTR_EXTENDED_ADDR, device_address ) ) ||
			( !is_extended_address( device_address ) && nla_put_u16( reply, NL802154_ATTR_SHORT_ADDR, (u16)device_address ) )
		);
	if ( 0 != r ) {
		dev_err( &dev->dev, "nla_put_failure (%d)\n", r );
		goto nla_put_failure;
	}

	genlmsg_end( reply, hdr );

	r = genlmsg_reply( reply, info );
	if ( 0 != r ) {
		dev_err( &dev->dev, "genlmsg_reply failed (%d)\n", r );
	}
	goto out;

nla_put_failure:
free_reply:
	nlmsg_free( reply );
out:
	rdev_set_coord_addr_mode( rdev, wpan_dev, IEEE802154_ADDR_NONE );
	rdev_set_coord_short_addr( rdev, wpan_dev, IEEE802154_ADDR_UNDEF );
	rdev_set_coord_extended_addr( rdev, wpan_dev, IEEE802154_PANID_BROADCAST );

	rdev_set_addr_mode( rdev, wpan_dev, IEEE802154_ADDR_NONE );
	rdev_set_short_addr( rdev, wpan_dev, IEEE802154_ADDR_UNDEF );
	rdev_set_pan_id( rdev, wpan_dev, IEEE802154_PANID_BROADCAST );
	return;
}


static int
nl802154_send_disassoc_req(struct wpan_phy *wpan_phy, struct wpan_dev *wpan_dev,
						u16 device_panid, u64 device_address,
						u8 disassociate_reason, u8 tx_indirect)
{
	int r;

	struct sk_buff *skb;
	struct ieee802154_mac_cb *cb;
	int hlen, tlen, size;
	struct ieee802154_addr dst_addr, src_addr;
	unsigned char *data;

	struct net_device *netdev = wpan_dev->netdev;
	struct device *logdev = &netdev->dev;

	memset( &src_addr, 0, sizeof( src_addr ) );
	memset( &dst_addr, 0, sizeof( dst_addr ) );

	//Create beacon frame / payload
	hlen = LL_RESERVED_SPACE(wpan_dev->netdev);
	tlen = wpan_dev->netdev->needed_tailroom;
	size = 2; //Todo: Replace magic number. Comes from ieee std 802154 "Association Request Frame Format" with a define

	dev_dbg( logdev, "The skb lengths used are hlen: %d, tlen %d, and size %d\n", hlen, tlen, size);
	dev_dbg( logdev, "Address of the netdev device structure: %p\n", wpan_dev->netdev );
	// dev_dbg( logdev, "Address of ieee802154_local * local from wpan_phy_priv: %p\n", local );

	skb = alloc_skb( hlen + tlen + size, GFP_KERNEL );
	if (!skb){
		r = -ENOMEM;
		goto error;
	}

	skb_reserve(skb, hlen);

	skb_reset_network_header(skb);

	data = skb_put(skb, size);

	src_addr.mode = wpan_dev->addr_mode;
	src_addr.pan_id = wpan_dev->pan_id;
	if ( IEEE802154_ADDR_LONG == src_addr.mode ) {
		src_addr.extended_addr = wpan_dev->extended_addr;
	} else {
		src_addr.short_addr = wpan_dev->short_addr;
	}

	dst_addr.mode = wpan_dev->coord_addr_mode;
	dst_addr.pan_id = wpan_dev->pan_id;
	if ( IEEE802154_ADDR_SHORT == dst_addr.mode ){
		dst_addr.short_addr = wpan_dev->coord_short_addr;
	} else {
		dst_addr.extended_addr = wpan_dev->coord_extended_addr;
	}

	cb = mac_cb_init(skb);
	cb->type = IEEE802154_FC_TYPE_MAC_CMD;
	cb->ackreq = true;

	cb->secen = false;
	cb->secen_override = false;
	cb->seclevel = 0;

	cb->source = src_addr;
	cb->dest = dst_addr;

	dev_dbg( logdev, "DSN value in wpan_dev: %p\n", &wpan_dev->dsn);

	dev_dbg( logdev, "Dest addr: 0x%04x\n", dst_addr.short_addr );
	dev_dbg( logdev, "Dest addr long: 0x%016" PRIx64 "\n", dst_addr.extended_addr );
	dev_dbg( logdev, "Src addr: 0x%04x\n", src_addr.short_addr );
	dev_dbg( logdev, "Src addr long: 0x%016" PRIx64 "\n", src_addr.extended_addr );

	netdev->header_ops->create( skb, netdev, ETH_P_IEEE802154, &dst_addr, &src_addr, hlen + tlen + size);

	dev_dbg( logdev, "Header is created");

	//Add the mac header to the data
	memcpy( data, cb, size );
	data[0] = IEEE802154_CMD_DISASSOCIATION_NOTIFY;
	data[1] = disassociate_reason;

	skb->dev = wpan_dev->netdev;
	skb->protocol = htons(ETH_P_IEEE802154);

	dev_dbg( logdev, "Data bytes sent out %x, %x\n",data[0], data[1]);

	r = ieee802154_subif_start_xmit( skb, wpan_dev->netdev );
	dev_dbg( logdev, "r value is %x\n", r );
	if( 0 == r) {
		goto error;
	}

	r = 0;
	goto out;

error:
	kfree_skb(skb);
out:
	return r;
}

static void nl802154_disassoc_req_complete( struct sk_buff *skb_in, void *arg ) {

	struct work_struct *work = (struct work_struct *)arg;
	struct work802154 *wrk = container_of( to_delayed_work( work ), struct work802154, work );

	struct genl_info *info = wrk->info;
	struct sk_buff *skb_out = wrk->skb;

	struct cfg802154_registered_device *rdev = info->user_ptr[0];
	struct net_device *dev = info->user_ptr[1];
	struct wpan_dev *wpan_dev = dev->ieee802154_ptr;

	u8 status = MAC_ERR_NO_DATA;

	dev_info( &dev->dev, "%s\n", __FUNCTION__ );

	cancel_delayed_work( &wrk->work );

	rdev_deregister_disassoc_req_listener( rdev, wpan_dev, nl802154_disassoc_req_complete, work );

	nl802154_disassoc_cnf( skb_out, wrk->info, status, wrk->cmd_stuff.disassoc.device_panid, wrk->cmd_stuff.disassoc.device_address );

	complete( &wrk->completion );
	kfree( wrk );
}

static void nl802154_disassoc_req_timeout( struct work_struct *work ) {

	static const u8 status = MAC_ERR_NO_ACK;

	struct work802154 *wrk = container_of( to_delayed_work( work ), struct work802154, work );

	struct genl_info *info = wrk->info;
	struct sk_buff *skb_out = wrk->skb;

	struct cfg802154_registered_device *rdev = info->user_ptr[0];
	struct net_device *dev = info->user_ptr[1];
	struct wpan_dev *wpan_dev = dev->ieee802154_ptr;

	dev_err( &dev->dev, "%s\n", __FUNCTION__ );

	rdev_deregister_disassoc_req_listener( rdev, wpan_dev, nl802154_disassoc_req_complete, (void *)work );

	nl802154_disassoc_cnf( skb_out, wrk->info, status, wrk->cmd_stuff.disassoc.device_panid, wrk->cmd_stuff.disassoc.device_address );

	complete( &wrk->completion );
	kfree( wrk );
}

static int nl802154_disassoc_req( struct sk_buff *skb, struct genl_info *info )
{
	int r;

	u8 device_addr_mode;
	u16 device_panid;
	u64 device_address;
	u8 disassociate_reason;
	u8 tx_indirect;
	u16 timeout_ms;
//	XXX: TODO
//	u32 security_level;
//	u32 key_id_mode;
//	u64 key_source;
//	u32 key_index;

	struct cfg802154_registered_device *rdev = info->user_ptr[0];
	struct net_device *dev = info->user_ptr[1];
	struct wpan_dev *wpan_dev = dev->ieee802154_ptr;

	struct work802154 *wrk;

	if ( ! (
		info->attrs[ NL802154_ATTR_ADDR_MODE ] &&
		info->attrs[ NL802154_ATTR_PAN_ID ] &&
		(
			info->attrs[ NL802154_ATTR_SHORT_ADDR ] ||
			info->attrs[ NL802154_ATTR_EXTENDED_ADDR ]
		) &&
		info->attrs[ NL802154_ATTR_DISASSOC_REASON ] &&
		info->attrs[ NL802154_ATTR_DISASSOC_TX_INDIRECT ] &&
		info->attrs[ NL802154_ATTR_DISASSOC_TIMEOUT_MS ]
	) ) {
		dev_err( &dev->dev, "invalid arguments\n" );
		r = -EINVAL;
		goto out;
	}

	device_addr_mode = nla_get_u8( info->attrs[ NL802154_ATTR_ADDR_MODE ] );
	device_panid = nla_get_u16( info->attrs[ NL802154_ATTR_PAN_ID ] );
	switch( device_addr_mode ) {
	case IEEE802154_ADDR_SHORT:
		if ( info->attrs[ NL802154_ATTR_SHORT_ADDR ] ) {
			device_address = nla_get_u16( info->attrs[ NL802154_ATTR_SHORT_ADDR ] );
			break;
		}
		/* no break */
	case IEEE802154_ADDR_LONG:
		if ( info->attrs[ NL802154_ATTR_EXTENDED_ADDR ] ) {
			device_address = nla_get_u64( info->attrs[ NL802154_ATTR_EXTENDED_ADDR ] );
			break;
		}
		/* no break */
	default:
		r = -EINVAL;
		goto out;
	}
	disassociate_reason = nla_get_u8( info->attrs[ NL802154_ATTR_DISASSOC_REASON ] );
	tx_indirect = nla_get_u8( info->attrs[ NL802154_ATTR_DISASSOC_TX_INDIRECT ] );
	timeout_ms = nla_get_u16( info->attrs[ NL802154_ATTR_DISASSOC_TIMEOUT_MS ] );

	wrk = kzalloc( sizeof( *wrk ), GFP_KERNEL );
	if ( NULL == wrk ) {
		r = -ENOMEM;
		goto out;
	}

	wrk->cmd = NL802154_CMD_DISASSOC_REQ;
	wrk->skb = skb;
	wrk->info = info;
	wrk->cmd_stuff.disassoc.device_panid = device_panid;
	wrk->cmd_stuff.disassoc.device_address = device_address;

	init_completion( &wrk->completion );
	INIT_DELAYED_WORK( &wrk->work, nl802154_disassoc_req_timeout );

	r = rdev_register_disassoc_req_listener( rdev, wpan_dev, nl802154_disassoc_req_complete, wrk );
	if ( 0 != r ) {
		dev_err( &dev->dev, "rdev_register_disassoc_listener failed (%d)\n", r );
		goto free_wrk;
	}

	r = nl802154_send_disassoc_req( &rdev->wpan_phy, wpan_dev, device_panid, device_address, disassociate_reason, tx_indirect );
	if ( 0 != r ) {
		dev_err( &dev->dev, "rdev_disassoc_req failed (%d)\n", r );
		goto dereg_listener;
	}

	r = schedule_delayed_work( &wrk->work, msecs_to_jiffies( timeout_ms ) ) ? 0 : -EALREADY;
	if ( 0 != r ) {
		dev_err( &dev->dev, "schedule_delayed_work failed (%d)\n", r );
		goto dereg_listener;
	}

	wait_for_completion( &wrk->completion );

	r = 0;
	goto out;

dereg_listener:
	rdev_deregister_disassoc_req_listener( rdev, wpan_dev, nl802154_disassoc_req_complete, (void *) &wrk->work.work );

free_wrk:
	kfree( wrk );

out:
	return r;
}

#define NL802154_FLAG_NEED_WPAN_PHY	0x01
#define NL802154_FLAG_NEED_NETDEV	0x02
#define NL802154_FLAG_NEED_RTNL		0x04
#define NL802154_FLAG_CHECK_NETDEV_UP	0x08
#define NL802154_FLAG_NEED_NETDEV_UP	(NL802154_FLAG_NEED_NETDEV |\
					 NL802154_FLAG_CHECK_NETDEV_UP)
#define NL802154_FLAG_NEED_WPAN_DEV	0x10
#define NL802154_FLAG_NEED_WPAN_DEV_UP	(NL802154_FLAG_NEED_WPAN_DEV |\
					 NL802154_FLAG_CHECK_NETDEV_UP)

static int nl802154_pre_doit(const struct genl_ops *ops, struct sk_buff *skb,
			     struct genl_info *info)
{
	struct cfg802154_registered_device *rdev;
	struct wpan_dev *wpan_dev;
	struct net_device *dev;
	bool rtnl = ops->internal_flags & NL802154_FLAG_NEED_RTNL;

	if (rtnl)
		rtnl_lock();

	if (ops->internal_flags & NL802154_FLAG_NEED_WPAN_PHY) {
		rdev = cfg802154_get_dev_from_info(genl_info_net(info), info);
		if (IS_ERR(rdev)) {
			if (rtnl)
				rtnl_unlock();
			return PTR_ERR(rdev);
		}
		info->user_ptr[0] = rdev;
	} else if (ops->internal_flags & NL802154_FLAG_NEED_NETDEV ||
		   ops->internal_flags & NL802154_FLAG_NEED_WPAN_DEV) {
		ASSERT_RTNL();
		wpan_dev = __cfg802154_wpan_dev_from_attrs(genl_info_net(info),
							   info->attrs);
		if (IS_ERR(wpan_dev)) {
			if (rtnl)
				rtnl_unlock();
			return PTR_ERR(wpan_dev);
		}

		dev = wpan_dev->netdev;
		rdev = wpan_phy_to_rdev(wpan_dev->wpan_phy);

		if (ops->internal_flags & NL802154_FLAG_NEED_NETDEV) {
			if (!dev) {
				if (rtnl)
					rtnl_unlock();
				return -EINVAL;
			}
			info->user_ptr[1] = dev;
		} else {
			info->user_ptr[1] = wpan_dev;
		}

		if (dev) {
			if (ops->internal_flags & NL802154_FLAG_CHECK_NETDEV_UP &&
			    !netif_running(dev)) {
				if (rtnl)
					rtnl_unlock();
				return -ENETDOWN;
			}

			dev_hold(dev);
		}

		info->user_ptr[0] = rdev;
	}

	return 0;
}

static void nl802154_post_doit(const struct genl_ops *ops, struct sk_buff *skb,
			       struct genl_info *info)
{
	if (info->user_ptr[1]) {
		if (ops->internal_flags & NL802154_FLAG_NEED_WPAN_DEV) {
			struct wpan_dev *wpan_dev = info->user_ptr[1];

			if (wpan_dev->netdev)
				dev_put(wpan_dev->netdev);
		} else {
			dev_put(info->user_ptr[1]);
		}
	}

	if (ops->internal_flags & NL802154_FLAG_NEED_RTNL)
		rtnl_unlock();
}

static const struct genl_ops nl802154_ops[] = {
	{
		.cmd = NL802154_CMD_GET_WPAN_PHY,
		.doit = nl802154_get_wpan_phy,
		.dumpit = nl802154_dump_wpan_phy,
		.done = nl802154_dump_wpan_phy_done,
		.policy = nl802154_policy,
		/* can be retrieved by unprivileged users */
		.internal_flags = NL802154_FLAG_NEED_WPAN_PHY |
				  NL802154_FLAG_NEED_RTNL,
	},
	{
		.cmd = NL802154_CMD_GET_INTERFACE,
		.doit = nl802154_get_interface,
		.dumpit = nl802154_dump_interface,
		.policy = nl802154_policy,
		/* can be retrieved by unprivileged users */
		.internal_flags = NL802154_FLAG_NEED_WPAN_DEV |
				  NL802154_FLAG_NEED_RTNL,
	},
	{
		.cmd = NL802154_CMD_NEW_INTERFACE,
		.doit = nl802154_new_interface,
		.policy = nl802154_policy,
		.flags = GENL_ADMIN_PERM,
		.internal_flags = NL802154_FLAG_NEED_WPAN_PHY |
				  NL802154_FLAG_NEED_RTNL,
	},
	{
		.cmd = NL802154_CMD_DEL_INTERFACE,
		.doit = nl802154_del_interface,
		.policy = nl802154_policy,
		.flags = GENL_ADMIN_PERM,
		.internal_flags = NL802154_FLAG_NEED_WPAN_DEV |
				  NL802154_FLAG_NEED_RTNL,
	},
	{
		.cmd = NL802154_CMD_SET_CHANNEL,
		.doit = nl802154_set_channel,
		.policy = nl802154_policy,
		.flags = GENL_ADMIN_PERM,
		.internal_flags = NL802154_FLAG_NEED_WPAN_PHY |
				  NL802154_FLAG_NEED_RTNL,
	},
	{
		.cmd = NL802154_CMD_SET_CCA_MODE,
		.doit = nl802154_set_cca_mode,
		.policy = nl802154_policy,
		.flags = GENL_ADMIN_PERM,
		.internal_flags = NL802154_FLAG_NEED_WPAN_PHY |
				  NL802154_FLAG_NEED_RTNL,
	},
	{
		.cmd = NL802154_CMD_SET_CCA_ED_LEVEL,
		.doit = nl802154_set_cca_ed_level,
		.policy = nl802154_policy,
		.flags = GENL_ADMIN_PERM,
		.internal_flags = NL802154_FLAG_NEED_WPAN_PHY |
				  NL802154_FLAG_NEED_RTNL,
	},
	{
		.cmd = NL802154_CMD_SET_TX_POWER,
		.doit = nl802154_set_tx_power,
		.policy = nl802154_policy,
		.flags = GENL_ADMIN_PERM,
		.internal_flags = NL802154_FLAG_NEED_WPAN_PHY |
				  NL802154_FLAG_NEED_RTNL,
	},
	{
		.cmd = NL802154_CMD_SET_PAN_ID,
		.doit = nl802154_set_pan_id,
		.policy = nl802154_policy,
		.flags = GENL_ADMIN_PERM,
		.internal_flags = NL802154_FLAG_NEED_NETDEV |
				  NL802154_FLAG_NEED_RTNL,
	},
	{
		.cmd = NL802154_CMD_SET_SHORT_ADDR,
		.doit = nl802154_set_short_addr,
		.policy = nl802154_policy,
		.flags = GENL_ADMIN_PERM,
		.internal_flags = NL802154_FLAG_NEED_NETDEV |
				  NL802154_FLAG_NEED_RTNL,
	},
	{
		.cmd = NL802154_CMD_SET_BACKOFF_EXPONENT,
		.doit = nl802154_set_backoff_exponent,
		.policy = nl802154_policy,
		.flags = GENL_ADMIN_PERM,
		.internal_flags = NL802154_FLAG_NEED_NETDEV |
				  NL802154_FLAG_NEED_RTNL,
	},
	{
		.cmd = NL802154_CMD_SET_MAX_CSMA_BACKOFFS,
		.doit = nl802154_set_max_csma_backoffs,
		.policy = nl802154_policy,
		.flags = GENL_ADMIN_PERM,
		.internal_flags = NL802154_FLAG_NEED_NETDEV |
				  NL802154_FLAG_NEED_RTNL,
	},
	{
		.cmd = NL802154_CMD_SET_MAX_FRAME_RETRIES,
		.doit = nl802154_set_max_frame_retries,
		.policy = nl802154_policy,
		.flags = GENL_ADMIN_PERM,
		.internal_flags = NL802154_FLAG_NEED_NETDEV |
				  NL802154_FLAG_NEED_RTNL,
	},
	{
		.cmd = NL802154_CMD_SET_LBT_MODE,
		.doit = nl802154_set_lbt_mode,
		.policy = nl802154_policy,
		.flags = GENL_ADMIN_PERM,
		.internal_flags = NL802154_FLAG_NEED_NETDEV |
				  NL802154_FLAG_NEED_RTNL,
	},
	{
		.cmd = NL802154_CMD_ED_SCAN_REQ,
		.doit = nl802154_ed_scan_req,
		.policy = nl802154_policy,
		.flags = GENL_ADMIN_PERM,
		.internal_flags = NL802154_FLAG_NEED_WPAN_PHY |
				  NL802154_FLAG_NEED_RTNL,
	},
	{
		.cmd = NL802154_CMD_ASSOC_REQ,
		.doit = nl802154_assoc_req,
		.policy = nl802154_policy,
		.flags = GENL_ADMIN_PERM,
		.internal_flags = NL802154_FLAG_NEED_NETDEV |
				  NL802154_FLAG_NEED_RTNL,
	},
	{
		.cmd = NL802154_CMD_ASSOC_RSP,
		.doit = nl802154_assoc_rsp,
		.policy = nl802154_policy,
		.flags = GENL_ADMIN_PERM,
		.internal_flags = NL802154_FLAG_NEED_NETDEV |
				  NL802154_FLAG_NEED_RTNL,
	},
	{
		.cmd = NL802154_CMD_GET_BEACON_NOTIFY,
		.doit = nl802154_get_beacon_indication,
		.policy = nl802154_policy,
		.flags = GENL_ADMIN_PERM,
		.internal_flags = NL802154_FLAG_NEED_WPAN_PHY |
				  NL802154_FLAG_NEED_RTNL,
	},
	{
		.cmd = NL802154_CMD_DISASSOC_REQ,
		.doit = nl802154_disassoc_req,
		.policy = nl802154_policy,
		.flags = GENL_ADMIN_PERM,
		.internal_flags = NL802154_FLAG_NEED_NETDEV |
				  NL802154_FLAG_NEED_RTNL,
	},
};

/* initialisation/exit functions */
int nl802154_init(void)
{
	return genl_register_family_with_ops_groups(&nl802154_fam, nl802154_ops,
						    nl802154_mcgrps);
}

void nl802154_exit(void)
{
	genl_unregister_family(&nl802154_fam);
}
