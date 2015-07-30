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
 * Based on: net/mac80211/cfg.c
 */

#include <net/rtnetlink.h>
#include <net/cfg802154.h>

#include "ieee802154_i.h"
#include "driver-ops.h"
#include "cfg.h"

static struct net_device *
ieee802154_add_iface_deprecated(struct wpan_phy *wpan_phy,
				const char *name,
				unsigned char name_assign_type, int type)
{
	struct ieee802154_local *local = wpan_phy_priv(wpan_phy);
	struct net_device *dev;

	rtnl_lock();
	dev = ieee802154_if_add(local, name, name_assign_type, type,
				cpu_to_le64(0x0000000000000000ULL));
	rtnl_unlock();

	return dev;
}

static void ieee802154_del_iface_deprecated(struct wpan_phy *wpan_phy,
					    struct net_device *dev)
{
	struct ieee802154_sub_if_data *sdata = IEEE802154_DEV_TO_SUB_IF(dev);

	ieee802154_if_remove(sdata);
}

#ifdef CONFIG_PM
static int ieee802154_suspend(struct wpan_phy *wpan_phy)
{
	struct ieee802154_local *local = wpan_phy_priv(wpan_phy);

	if (!local->open_count)
		goto suspend;

	ieee802154_stop_queue(&local->hw);
	synchronize_net();

	/* stop hardware - this must stop RX */
	ieee802154_stop_device(local);

suspend:
	local->suspended = true;
	return 0;
}

static int ieee802154_resume(struct wpan_phy *wpan_phy)
{
	struct ieee802154_local *local = wpan_phy_priv(wpan_phy);
	int ret;

	/* nothing to do if HW shouldn't run */
	if (!local->open_count)
		goto wake_up;

	/* restart hardware */
	ret = drv_start(local);
	if (ret)
		return ret;

wake_up:
	ieee802154_wake_queue(&local->hw);
	local->suspended = false;
	return 0;
}
#else
#define ieee802154_suspend NULL
#define ieee802154_resume NULL
#endif

static int
ieee802154_add_iface(struct wpan_phy *phy, const char *name,
		     unsigned char name_assign_type,
		     enum nl802154_iftype type, __le64 extended_addr)
{
	struct ieee802154_local *local = wpan_phy_priv(phy);
	struct net_device *err;

	err = ieee802154_if_add(local, name, name_assign_type, type,
				extended_addr);
	return PTR_ERR_OR_ZERO(err);
}

static int
ieee802154_del_iface(struct wpan_phy *wpan_phy, struct wpan_dev *wpan_dev)
{
	ieee802154_if_remove(IEEE802154_WPAN_DEV_TO_SUB_IF(wpan_dev));

	return 0;
}

static int
ieee802154_set_channel(struct wpan_phy *wpan_phy, u8 page, u8 channel)
{
	struct ieee802154_local *local = wpan_phy_priv(wpan_phy);
	int ret;

	ASSERT_RTNL();

	if (wpan_phy->current_page == page &&
	    wpan_phy->current_channel == channel)
		return 0;

	ret = drv_set_channel(local, page, channel);
	if (!ret) {
		wpan_phy->current_page = page;
		wpan_phy->current_channel = channel;
	}

	return ret;
}

static int
ieee802154_set_cca_mode(struct wpan_phy *wpan_phy,
			const struct wpan_phy_cca *cca)
{
	struct ieee802154_local *local = wpan_phy_priv(wpan_phy);
	int ret;

	ASSERT_RTNL();

	if (wpan_phy_cca_cmp(&wpan_phy->cca, cca))
		return 0;

	ret = drv_set_cca_mode(local, cca);
	if (!ret)
		wpan_phy->cca = *cca;

	return ret;
}

static int
ieee802154_set_cca_ed_level(struct wpan_phy *wpan_phy, s32 ed_level)
{
	struct ieee802154_local *local = wpan_phy_priv(wpan_phy);
	int ret;

	ASSERT_RTNL();

	if (wpan_phy->cca_ed_level == ed_level)
		return 0;

	ret = drv_set_cca_ed_level(local, ed_level);
	if (!ret)
		wpan_phy->cca_ed_level = ed_level;

	return ret;
}

static int
ieee802154_set_tx_power(struct wpan_phy *wpan_phy, s32 power)
{
	struct ieee802154_local *local = wpan_phy_priv(wpan_phy);
	int ret;

	ASSERT_RTNL();

	if (wpan_phy->transmit_power == power)
		return 0;

	ret = drv_set_tx_power(local, power);
	if (!ret)
		wpan_phy->transmit_power = power;

	return ret;
}

static int
ieee802154_set_pan_id(struct wpan_phy *wpan_phy, struct wpan_dev *wpan_dev,
		      __le16 pan_id)
{
	int ret;

	ASSERT_RTNL();

	if (wpan_dev->pan_id == pan_id)
		return 0;

	ret = mac802154_wpan_update_llsec(wpan_dev->netdev);
	if (!ret)
		wpan_dev->pan_id = pan_id;

	return ret;
}

static int
ieee802154_set_backoff_exponent(struct wpan_phy *wpan_phy,
				struct wpan_dev *wpan_dev,
				u8 min_be, u8 max_be)
{
	ASSERT_RTNL();

	if (wpan_dev->min_be == min_be &&
	    wpan_dev->max_be == max_be)
		return 0;

	wpan_dev->min_be = min_be;
	wpan_dev->max_be = max_be;
	return 0;
}

static int
ieee802154_set_short_addr(struct wpan_phy *wpan_phy, struct wpan_dev *wpan_dev,
			  __le16 short_addr)
{
	ASSERT_RTNL();

	if (wpan_dev->short_addr == short_addr)
		return 0;

	wpan_dev->short_addr = short_addr;
	return 0;
}

static int
ieee802154_set_max_csma_backoffs(struct wpan_phy *wpan_phy,
				 struct wpan_dev *wpan_dev,
				 u8 max_csma_backoffs)
{
	ASSERT_RTNL();

	if (wpan_dev->csma_retries == max_csma_backoffs)
		return 0;

	wpan_dev->csma_retries = max_csma_backoffs;
	return 0;
}

static int
ieee802154_set_max_frame_retries(struct wpan_phy *wpan_phy,
				 struct wpan_dev *wpan_dev,
				 s8 max_frame_retries)
{
	ASSERT_RTNL();

	if (wpan_dev->frame_retries == max_frame_retries)
		return 0;

	wpan_dev->frame_retries = max_frame_retries;
	return 0;
}

static int
ieee802154_set_lbt_mode(struct wpan_phy *wpan_phy, struct wpan_dev *wpan_dev,
			bool mode)
{
	ASSERT_RTNL();

	if (wpan_dev->lbt == mode)
		return 0;

	wpan_dev->lbt = mode;
	return 0;
}

static int
ieee802154_ed_scan(struct wpan_phy *wpan_phy, struct wpan_dev *wpan_dev,
            u8 page, u32 channels, u8 *level, size_t nlevel, u8 duration)
{
	struct ieee802154_local *local = wpan_phy_priv(wpan_phy);
	int ret = 0;

	ASSERT_RTNL();

	ret = drv_ed_scan( local, page, channels, level, nlevel, duration );

	return ret;
}

static int
ieee802154_assoc_req(struct wpan_phy *wpan_phy, struct wpan_dev *wpan_dev,
		u8 channel_number, u8 channel_page,  u8 addr_mode, u16 coord_pan_id, u64 coord_addr,
		u8 capability_information, u64 src_addr ){

	int r = 0;
	struct sk_buff *skb;
	struct ieee802154_mac_cb *cb;
	int hlen, tlen, size;
	struct ieee802154_addr dst_addr, source_addr;
	unsigned char *data;

	printk(KERN_INFO "Inside %s\n", __FUNCTION__);

	struct ieee802154_local * local = wpan_phy_priv(wpan_phy);

	//Create beacon frame / payload
	hlen = LL_RESERVED_SPACE(wpan_dev->netdev);
	tlen = wpan_dev->netdev->needed_tailroom;
	size = 2; //Todo: Replace magic number. Comes from ieee std 802154 "Association Request Frame Format" with a define

	printk( KERN_INFO "The skb lengths used are hlen: %d, tlen %d, and size %d\n", hlen, tlen, size);
	printk( KERN_INFO "Address of the netdev device structure: %x\n", wpan_dev->netdev );
	printk( KERN_INFO "Address of ieee802154_local * local from wpan_phy_priv: %x\n", local );

	//Subvert and populate the ieee802154_local pointer in ieee802154_sub_if_data
	struct ieee802154_sub_if_data *sdata = IEEE802154_DEV_TO_SUB_IF(wpan_dev->netdev);
	sdata->local = local;

	skb = alloc_skb( hlen + tlen + size, GFP_KERNEL );
	if (!skb){
		goto error;
	}

	skb_reserve(skb, hlen);

	skb_reset_network_header(skb);

	data = skb_put(skb, size);

	source_addr.mode = IEEE802154_ADDR_LONG;
	dst_addr.mode = addr_mode;
	dst_addr.pan_id = coord_pan_id;

	if ( IEEE802154_ADDR_SHORT == addr_mode ){
		dst_addr.short_addr = (u16*)coord_addr;
	} else {
		dst_addr.long_addr = coord_addr;
	}

	cb = mac_cb_init(skb);
	cb->type = IEEE802154_FC_TYPE_MAC_CMD;
	cb->ackreq = false;

	cb->secen = false;
	cb->secen_override = false;
	cb->seclevel = 0;

	cb->source = source_addr;
	cb->dest = dst_addr;

	printk( KERN_INFO "DSN value in wpan_dev: %x\n", &wpan_dev->dsn );
	//Since the existing subroutine for creating the mac header doesn't seem to work in this situation, will be rewriting it it with a correction here
	r = ieee802154_header_create( skb, wpan_dev, ETH_P_IEEE802154, &dst_addr, &source_addr, hlen + tlen + size);

	//Add the mac header to the data
	r = memcpy( data, cb, size );
	data[0] = IEEE802154_CMD_ASSOCIATION_REQ;
	data[1] = capability_information;

	skb->dev = wpan_dev->netdev;
	skb->protocol = htons(ETH_P_IEEE802154);

	printk( KERN_INFO "Data bytes sent out %x, %x, %x, %x, %x, %x, %x, %x ",data[0], data[1],data[2], data[3],data[4], data[5],data[6], data[7]  );

//	r = drv_xmit_async( local, skb );
	r = ieee802154_subif_start_xmit( skb, wpan_dev->netdev );
	if( 0 == r) {
		goto out;
	}


error:
	kfree_skb(skb);
out:
	return r;
}

const struct cfg802154_ops mac802154_config_ops = {
	.add_virtual_intf_deprecated = ieee802154_add_iface_deprecated,
	.del_virtual_intf_deprecated = ieee802154_del_iface_deprecated,
	.suspend = ieee802154_suspend,
	.resume = ieee802154_resume,
	.add_virtual_intf = ieee802154_add_iface,
	.del_virtual_intf = ieee802154_del_iface,
	.set_channel = ieee802154_set_channel,
	.set_cca_mode = ieee802154_set_cca_mode,
	.set_cca_ed_level = ieee802154_set_cca_ed_level,
	.set_tx_power = ieee802154_set_tx_power,
	.set_pan_id = ieee802154_set_pan_id,
	.set_short_addr = ieee802154_set_short_addr,
	.set_backoff_exponent = ieee802154_set_backoff_exponent,
	.set_max_csma_backoffs = ieee802154_set_max_csma_backoffs,
	.set_max_frame_retries = ieee802154_set_max_frame_retries,
	.set_lbt_mode = ieee802154_set_lbt_mode,
	.ed_scan = ieee802154_ed_scan,
	.assoc_req = ieee802154_assoc_req,
};
