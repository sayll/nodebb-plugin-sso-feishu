define('admin/plugins/sso-feishu', ['settings'], function(Settings) {
	'use strict';
	/* globals $, app, socket, require */

	var ACP = {};

	ACP.init = function() {
		Settings.load('sso-feishu', $('.sso-feishu-settings'));

		$('#save').on('click', function() {
			Settings.save('sso-feishu', $('.sso-feishu-settings'), function() {
				app.alert({
					type: 'success',
					alert_id: 'sso-feishu-saved',
					title: 'Settings Saved',
					message: 'Please reload your NodeBB to apply these settings',
					clickfn: function() {
						socket.emit('admin.reload');
					}
				});
			});
		});
	};

	return ACP;
});