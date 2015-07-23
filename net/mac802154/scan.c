/*
 * scan.c
 *
 *  Created on: Jul 17, 2015
 *      Author: magyarm
 *
 *      802154 Scanning implementation based on 80211 scanning
 */

#include <linux/rtnetlink.h>

#include <net/mac802154.h>

#include "ieee802154_i.h"
#include "driver-ops.h"

void ieee802154_scan_work(struct work_struct *work)
{
	struct work802154 *wrk = container_of( work, struct work802154, work );
	struct ieee802154_local *local = local_scan_work->local;
	struct wpan_phy *phy = container_of( local, struct wpan_phy, phy );
	unsigned char ed_list[32];
	memset( ed_list, 0xff, sizeof( ed_list ) );


	// Populate a MLME-SCAN.confirm message structure that will get passed to a netlink message creation function


	// Free the work
	free( work );
}
