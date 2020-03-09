<?php
/**
 * Options for the forceuserchange plugin
 *
 * @author Henry Pan <dokuwiki.plugin@phy25.com>
 */

$meta['groupname'] = array('string');
$meta['grouprel'] = array('multichoice', '_choices'=>array('including', 'excluding'));
$meta['allowsamepw'] = array('onoff');
