<?php
/**
 * DokuWiki Plugin forceuserchange (Action Component)
 *
 * @license GPL 2 http://www.gnu.org/licenses/gpl-2.0.html
 * @author  Henry Pan <dokuwiki.plugin@phy25.com>
 */

// must be run within Dokuwiki
if (!defined('DOKU_INC')) {
    die();
}

class action_plugin_forceuserchange extends DokuWiki_Action_Plugin
{
    const PROFILE_ACT_NAME = 'profile';

    /**
     * Registers a callback function for a given event
     *
     * @param Doku_Event_Handler $controller DokuWiki's event controller object
     *
     * @return void
     */
    public function register(Doku_Event_Handler $controller)
    {
        $controller->register_hook('AUTH_LOGIN_CHECK', 'AFTER', $this, 'handle_auth_login_check');
        $controller->register_hook('ACTION_ACT_PREPROCESS', 'BEFORE', $this, 'handle_action_act_preprocess');
        $controller->register_hook('ACTION_HEADERS_SEND', 'AFTER', $this, 'handle_tpl_act_render');
        $controller->register_hook('AUTH_USER_CHANGE', 'AFTER', $this, 'handle_auth_user_change');
        if (!$this->getConf('allowsamepw')){
            $controller->register_hook('AUTH_USER_CHANGE', 'BEFORE', $this, 'prevent_same_password');
        }
    }

    public function handle_auth_login_check(Doku_Event $event, $param)
    {
        if ($event->result == true) {
            // logged in
            if ($this->user_required_to_stop()) {
                // if slient (e.g. rpc, cookie) then reject the login
                // since we won't have a chance to redirect user to profile change
                if ($event->data['silent']) {
                    auth_logoff();
                    $event->result = false;
                    return;
                }
            }
        }
    }

    public function handle_action_act_preprocess(Doku_Event $event, $param)
    {
        global $ID;
        if ($this->user_required_to_stop()) {
            if ($event->data != self::PROFILE_ACT_NAME) {
                // not silent: we need to redirect user to profile page, if they are not there
                // this is put here to prevent profile page rewriting $ACT after an attempt
                // but user is still required to change as required
                // when profile rewrites $ACT this will be called multiple times
                return send_redirect(wl($ID, array('do' => self::PROFILE_ACT_NAME), true, '&'));
            }
        }
    }

    /**
     * Inject message to inform user that they need to complete a change
     */
    public function handle_tpl_act_render(Doku_Event $event, $param)
    {
        global $ACT;
        if ($this->user_required_to_stop()) {
            if ($ACT == self::PROFILE_ACT_NAME) {
                msg(sprintf($this->getLang('msg_forceupdate'), $this->getConf('allowsamepw') ? $this->getLang('msg_sameallowed') : ''));
            }
        }
    }

    protected function get_user_groups($user = null) {
        global $USERINFO, $auth, $INPUT;
        $uinfo = $USERINFO;
        if ($user && $user !== $INPUT->server->str('REMOTE_USER')) {
            // fetch user info
            $uinfo = $auth->getUserData($user);
        }
        return (array) $uinfo['grps'];
    }

    protected function user_required_to_stop($user = null) {
        $grps = $this->get_user_groups($user);
        $has_group = array_search($this->getConf('groupname'), $grps) !== false;
        if ($this->getConf('grouprel') == 'excluding') {
            return !$has_group; // users not having the group are required to stop
        }else{
            return $has_group;
        }
    }

    /**
     * Change user group accordingly if user did the required change
     */
    public function handle_auth_user_change(Doku_Event $event, $param)
    {
        global $auth;
        if (
            $event->data['type'] == 'modify' && isset($event->data['params'][1]['pass']) &&
            $event->data['modification_result'] && $this->user_required_to_stop($event->data['params'][0])
            ) {
            // modify group
            $user = $event->data['params'][0];
            $grps = $this->get_user_groups($user);
            $key = array_search($this->getConf('groupname'), $grps);
            if ($this->getConf('grouprel') == 'including') {
                if ($key !== false) {
                    array_splice($grps, $key, 1);
                    $auth->triggerUserMod('modify', array($user, array('grps'=>$grps)));
                }
            } else {
                if ($key === false) {
                    $grps[] = $this->getConf('groupname');
                    $auth->triggerUserMod('modify', array($user, array('grps'=>$grps)));
                }
            }
        }
    }

    public function prevent_same_password(Doku_Event $event, $param)
    {
        global $auth, $INPUT;
        if (
            $event->data['type'] == 'modify' && isset($event->data['params'][1]['pass']) &&
            $event->data['params'][0] == $INPUT->server->str('REMOTE_USER') &&
            $this->user_required_to_stop($event->data['params'][0])
            )
        {
            // check password
            $user = $event->data['params'][0];
            $pass = $event->data['params'][1]['pass'];
            if (!$auth->canDo('external') && $auth->checkPass($user, $pass)){
                // same password
                $event->preventDefault();
                msg($this->getLang('msg_errorpw'), -1);
            }
        }
    }
}
