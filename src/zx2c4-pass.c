#define PURPLE_PLUGINS

#include "config.h"

#include <string.h>
#include <glib.h>
#include <glib/gprintf.h>

#include <pidgin.h>
#include <plugin.h>
#include <gtkplugin.h>
#include <version.h>
#include <account.h>
#include <signal.h>

PurplePlugin* pass_plugin = NULL;

static gchar*
zx2c4_pass_cmdline(const PurpleAccount* account, const gchar* command) {
	gchar* username = g_strdup(purple_account_get_username(account));

	/* strips resource info from jid */
	gchar* slash_pos = strchr(username, '/');
	if (slash_pos != NULL) *slash_pos = '\0';

	gchar* cmd = g_strdup_printf("%s %s %s/%s/%s",
		purple_prefs_get_string("/plugins/core/zx2c4_pass/script"),
		command,
		purple_prefs_get_string("/plugins/core/zx2c4_pass/path"),
		purple_account_get_protocol_id(account),
		username
	);
	g_free(username);
	return cmd;
}

static gchar*
zx2c4_pass_lookup(const PurpleAccount* account) {
	gchar* cmd = zx2c4_pass_cmdline(account, "show");
	FILE* in = popen(cmd, "r");
	g_free(cmd);

	gchar* password = NULL;
	if (in) {
		gchar buff[64];
		if (fgets(buff, sizeof(buff), in) != NULL) {
			g_strchomp(buff);
			password = g_strdup(buff);
		}
		pclose(in);
	} else {
		purple_notify_error(pass_plugin, "Error", "Password lookup error", "Unable to run pass script");
	}
	return password;
}

static void
zx2c4_pass_store(const PurpleAccount* account) {
	gchar* cmd = zx2c4_pass_cmdline(account, "insert");
	FILE* out = popen(cmd, "w");
	g_free(cmd);

	if (out) {
		g_fprintf(out, "%1$s\n%1$s\n", purple_account_get_password(account));
		pclose(out);
	} else {
		purple_notify_error(pass_plugin, "Error", "Password store error", "Unable to run pass script");
	}
}

/* callback to whenever an account is enabled */
static void
acct_enable_cb(PurpleAccount* account, gpointer data) {
	if (purple_account_get_password(account) == NULL) {
		gchar* password = zx2c4_pass_lookup(account);
		if (password != NULL) {
			purple_account_set_password(account, password);
			g_free(password);
		}
	}
}

/* calledback to whenever an account is signed in */
static void
acct_sign_in_cb(PurpleAccount* account, gpointer data) {
	if (!purple_account_get_remember_password(account)) return;

	const gchar* pidgin_password = purple_account_get_password(account);
	purple_account_set_remember_password(account, FALSE);
	if (pidgin_password == NULL) return;

	gchar* password = zx2c4_pass_lookup(account);
	if (password == NULL) {
		zx2c4_pass_store(account);
	} else {
		if (strcmp(password, pidgin_password) != 0)
			zx2c4_pass_store(account);
		g_free(password);
	}
}

static gboolean
plugin_load(PurplePlugin* plugin) {
	GList* accounts = purple_accounts_get_all();
	while (accounts) {
		PurpleAccount* account = accounts->data;
		if (purple_account_get_enabled(account, PIDGIN_UI)) {
			gchar* password = zx2c4_pass_lookup(account);
			if (password != NULL) {
				purple_account_set_password(account, password);
				g_free(password);
			} else
				if (purple_account_get_remember_password(account) &&
						purple_account_get_password(account) != NULL)
					zx2c4_pass_store(account);
			purple_account_set_remember_password(account, FALSE);
		}
		accounts = accounts->next;
	}

	void* accounts_handle = purple_accounts_get_handle();
	purple_signal_connect(accounts_handle, "account-enabled", plugin,
			PURPLE_CALLBACK(acct_enable_cb), NULL);
	purple_signal_connect(accounts_handle, "account-signed-on", plugin,
			PURPLE_CALLBACK(acct_sign_in_cb), NULL);

	pass_plugin = plugin;

	return TRUE;
}

static gboolean
plugin_unload(PurplePlugin* plugin) {
	void* accounts_handle = purple_accounts_get_handle();
	purple_signal_disconnect(accounts_handle, "account-signed-on", plugin, NULL);
	purple_signal_disconnect(accounts_handle, "account-enabled", plugin, NULL);
	return TRUE;
}

static PurplePluginPrefFrame*
get_pref_frame(PurplePlugin* plugin) {
	PurplePluginPrefFrame* frame = purple_plugin_pref_frame_new();
	purple_plugin_pref_frame_add(frame,
		purple_plugin_pref_new_with_name_and_label(
			"/plugins/core/zx2c4_pass/script",
			"Pass script"
		)
	);
	purple_plugin_pref_frame_add(frame,
		purple_plugin_pref_new_with_name_and_label(
			"/plugins/core/zx2c4_pass/path",
			"Password storage directory"
		)
	);
	return frame;
}


static PurplePluginUiInfo prefs_info = {
	get_pref_frame,
	0,
	NULL,

	NULL,
	NULL,
	NULL,
	NULL
};

static PurplePluginInfo info = {
	PURPLE_PLUGIN_MAGIC, PURPLE_MAJOR_VERSION, PURPLE_MINOR_VERSION,
	PURPLE_PLUGIN_STANDARD,
	PIDGIN_PLUGIN_TYPE,
	0,
	NULL,
	PURPLE_PRIORITY_HIGHEST,
	"core-zx2c4_pass",
	PACKAGE_NAME,
	VERSION,
	"Use zx2c4 pass to store pidgin passwords",
	"Use zx2c4 pass to store pidgin passwords",
	"Denimor <denimor@bk.ru>",
	PACKAGE_URL,
	plugin_load,
	plugin_unload,
	NULL,
	NULL,
	NULL,
	&prefs_info,
	NULL,

	NULL,
	NULL,
	NULL,
	NULL
};

static void
init_plugin(PurplePlugin* plugin) {
	purple_prefs_add_none("/plugins/core/zx2c4_pass");
	purple_prefs_add_string("/plugins/core/zx2c4_pass/path", "pidgin");
	purple_prefs_add_string("/plugins/core/zx2c4_pass/script", PASS_SCRIPT);
}

PURPLE_INIT_PLUGIN(zx2c4_pass, init_plugin, info)
