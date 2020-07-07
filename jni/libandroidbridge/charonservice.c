/*
 * Copyright (C) 2020 Webistics Holdings Ltd.
 * Copyright (C) 2012-2013 Tobias Brunner
 * Copyright (C) 2012 Giuliano Grassi
 * Copyright (C) 2012 Ralf Sager
 * Hochschule fuer Technik Rapperswil
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */
#include <signal.h>
#include <string.h>
#include <sys/utsname.h>
#include <android/log.h>
#include <errno.h>
#include <unistd.h>


#include "charonservice.h"
//#include "android_jni.h"
#include "backend/android_attr.h"
#include "backend/android_creds.h"
#include "backend/android_private_key.h"
#include "backend/android_service.h"
#include "kernel/android_ipsec.h"
#include "kernel/android_net.h"

#include "base64.h"
#include "certificates.h"

#ifdef USE_BYOD
#include "byod/imc_android.h"
#endif

#include <daemon.h>
#include <hydra.h>
#include <ipsec.h>
#include <library.h>
#include <threading/thread.h>

#include <pthread.h>

#define ANDROID_DEBUG_LEVEL 1
#define ANDROID_RETRASNMIT_TRIES 3
#define ANDROID_RETRANSMIT_TIMEOUT 2.0
#define ANDROID_RETRANSMIT_BASE 1.4
#define ANDROID_FRAGMENT_SIZE 1400

pthread_mutex_t connected_lock = PTHREAD_MUTEX_INITIALIZER;
bool connected = FALSE;
bool terminate_counter_thread = FALSE;

typedef struct private_charonservice_t private_charonservice_t;

/**
 * private data of charonservice
 */
struct private_charonservice_t {

	/**
	 * public interface
	 */
	charonservice_t public;

	/**
	 * android_attr instance
	 */
	android_attr_t *attr;

	/**
	 * android_creds instance
	 */
	android_creds_t *creds;

	/**
	 * android_service instance
	 */
	android_service_t *service;

	/**
	 * VpnService builder (accessed via JNI)
	 */
	vpnservice_builder_t *builder;

	/**
	 * NetworkManager instance (accessed via JNI)
	 */
	//network_manager_t *network_manager;

	/**
	 * Handle network events
	 */
	android_net_t *net_handler;

	/**
	 * CharonVpnService reference
	 */
	//jobject vpn_service;

	/**
	 * Sockets that were bypassed and we keep track for
	 */
	linked_list_t *sockets;


};

/**
 * Single instance of charonservice_t.
 */
charonservice_t *charonservice;

/**
 * hook in library for debugging messages
 */
extern void (*dbg)(debug_t group, level_t level, char *fmt, ...);

/**
 * Logging hook for library logs, using android specific logging
 */
static void dbg_android(debug_t group, level_t level, char *fmt, ...)
{
	va_list args;

	if (level <= ANDROID_DEBUG_LEVEL)
	{
		char sgroup[16], buffer[8192];
		char *current = buffer, *next;

		snprintf(sgroup, sizeof(sgroup), "%N", debug_names, group);
		va_start(args, fmt);
		vsnprintf(buffer, sizeof(buffer), fmt, args);
		va_end(args);
		while (current)
		{	/* log each line separately */
			next = strchr(current, '\n');
			if (next)
			{
				*(next++) = '\0';
			}
			__android_log_print(ANDROID_LOG_INFO, "charon", "00[%s] %s\n",
								sgroup, current);
			current = next;
		}
	}
}

METHOD(charonservice_t, check_and_update_status, void, private_charonservice_t *this)
{
	u_int connected = 0;
	u_int connecting = 0;
	ike_sa_t *ike_sa;
	enumerator_t *enumerator;

	enumerator = charon->ike_sa_manager->create_enumerator(
												charon->ike_sa_manager, TRUE);
	while (enumerator->enumerate(enumerator, &ike_sa))
	{
		ike_sa_state_t state = ike_sa->get_state(ike_sa);
		if (state == IKE_ESTABLISHED) {
				connected += 1;
		} else {
				connecting += 1;
		}

	}
/*
  count = charon->ike_sa_manager->get_count(charon->ike_sa_manager);
	half_open = charon->ike_sa_manager->get_half_open_count(charon->ike_sa_manager, NULL);
*/
	if (connecting > 0) {
			this->builder->update_status(this->builder, "CONNECTING");
	} else {
			if (connected > 0) {
					this->builder->update_status(this->builder, "CONNECTED");
			} else {
					this->builder->update_status(this->builder, "EXITING");
			}
	}
}

METHOD(charonservice_t, update_status, bool,
	private_charonservice_t *this, android_vpn_state_t code)
{
		DBG1(DBG_DMN, "update_status invoked %u", code);

		if (code == CHARONSERVICE_CHILD_STATE_UP) {
				DBG1(DBG_DMN, "update_status invoked state_up");
				pthread_mutex_lock(&connected_lock);
				connected = TRUE;
				pthread_mutex_unlock(&connected_lock);
				return this->builder->update_status(this->builder, "CONNECTED");
		} else {
				DBG1(DBG_DMN, "update_status invoked state_down");
				pthread_mutex_lock(&connected_lock);
				connected = FALSE;
				pthread_mutex_unlock(&connected_lock);
				return this->builder->update_status(this->builder, "EXITING");
		}
	  return FALSE;
/*
	JNIEnv *env;
	jmethodID method_id;
	bool success = FALSE;

	androidjni_attach_thread(&env);

	method_id = (*env)->GetMethodID(env, android_charonvpnservice_class,
									"updateStatus", "(I)V");
	if (!method_id)
	{
		goto failed;
	}
	(*env)->CallVoidMethod(env, this->vpn_service, method_id, (jint)code);
	success = !androidjni_exception_occurred(env);

failed:
	androidjni_exception_occurred(env);
	androidjni_detach_thread();
	return success;
*/

}

METHOD(charonservice_t, update_imc_state, bool,
	private_charonservice_t *this, android_imc_state_t state)
{
DBG1(DBG_DMN, "update_imc_state invoked");
/*
	JNIEnv *env;
	jmethodID method_id;
	bool success = FALSE;

	androidjni_attach_thread(&env);

	method_id = (*env)->GetMethodID(env, android_charonvpnservice_class,
									"updateImcState", "(I)V");
	if (!method_id)
	{
		goto failed;
	}
	(*env)->CallVoidMethod(env, this->vpn_service, method_id, (jint)state);
	success = !androidjni_exception_occurred(env);

failed:
	androidjni_exception_occurred(env);
	androidjni_detach_thread();
	return success;
*/
	return FALSE;
}

METHOD(charonservice_t, add_remediation_instr, bool,
	private_charonservice_t *this, char *instr)
{
	DBG1(DBG_DMN, "add_remediation_instr invoked");
/*
  JNIEnv *env;
	jmethodID method_id;
	jstring jinstr;
	bool success = FALSE;

	androidjni_attach_thread(&env);

	method_id = (*env)->GetMethodID(env, android_charonvpnservice_class,
									"addRemediationInstruction",
									"(Ljava/lang/String;)V");
	if (!method_id)
	{
		goto failed;
	}
	jinstr = (*env)->NewStringUTF(env, instr);
	if (!jinstr)
	{
		goto failed;
	}
	(*env)->CallVoidMethod(env, this->vpn_service, method_id, jinstr);
	success = !androidjni_exception_occurred(env);

failed:
	androidjni_exception_occurred(env);
	androidjni_detach_thread();
	return success;
*/
	return FALSE;
}

/**
 * Bypass a single socket
 */
static bool bypass_single_socket(intptr_t fd, private_charonservice_t *this)
{
	DBG1(DBG_DMN, "bypass_single_socket invoked");

	return this->builder->protect_socket(this->builder, fd);
/*
	JNIEnv *env;
	jmethodID method_id;

	androidjni_attach_thread(&env);

	method_id = (*env)->GetMethodID(env, android_charonvpnservice_class,
									"protect", "(I)Z");
	if (!method_id)
	{
		goto failed;
	}
	if (!(*env)->CallBooleanMethod(env, this->vpn_service, method_id, fd))
	{
		DBG2(DBG_KNL, "VpnService.protect() failed");
		goto failed;
	}
	androidjni_detach_thread();
	return TRUE;

failed:
	androidjni_exception_occurred(env);
	androidjni_detach_thread();
	return FALSE;
*/
}

METHOD(charonservice_t, bypass_socket, bool,
	private_charonservice_t *this, int fd, int family)
{
	if (fd >= 0)
	{
		this->sockets->insert_last(this->sockets, (void*)(intptr_t)fd);
		return bypass_single_socket((intptr_t)fd, this);
	}
	this->sockets->invoke_function(this->sockets, (void*)bypass_single_socket,
								   this);
	return TRUE;
}

void add_certificate_to_list(linked_list_t* list, char* cert)
{
		size_t output_length;
		chunk_t *chunk;
		chunk = malloc_thing(chunk_t);
		list->insert_last(list, chunk);
    unsigned char * cert_decoded = base64_decode(cert, strlen(cert), &output_length);
    *chunk = chunk_alloc(output_length);
    memcpy(chunk->ptr, cert_decoded, chunk->len);

}


METHOD(charonservice_t, get_trusted_certificates, linked_list_t*,
	private_charonservice_t *this)
{
		DBG1(DBG_DMN, "get_trusted_certificates invoked");

		build_decoding_table();
		linked_list_t *list;

		list = linked_list_create();

		add_certificate_to_list(list, LE_CA_CERT);
		add_certificate_to_list(list, LE_INT_CERT);

		base64_cleanup();

		return list;
/*
	JNIEnv *env;
	jmethodID method_id;
	jobjectArray jcerts;
	linked_list_t *list;

	androidjni_attach_thread(&env);

	method_id = (*env)->GetMethodID(env,
						android_charonvpnservice_class,
						"getTrustedCertificates", "()[[B");
	if (!method_id)
	{
		goto failed;
	}
	jcerts = (*env)->CallObjectMethod(env, this->vpn_service, method_id);
	if (!jcerts || androidjni_exception_occurred(env))
	{
		goto failed;
	}
	list = convert_array_of_byte_arrays(env, jcerts);
	androidjni_detach_thread();
	return list;

failed:
	androidjni_exception_occurred(env);
	androidjni_detach_thread();
	return NULL;
*/
	return NULL;
}

METHOD(charonservice_t, get_user_certificate, linked_list_t*,
	private_charonservice_t *this)
{
	DBG1(DBG_DMN, "get_user_certificate invoked");
/*
	JNIEnv *env;
	jmethodID method_id;
	jobjectArray jencodings;
	linked_list_t *list;

	androidjni_attach_thread(&env);

	method_id = (*env)->GetMethodID(env,
						android_charonvpnservice_class,
						"getUserCertificate", "()[[B");
	if (!method_id)
	{
		goto failed;
	}
	jencodings = (*env)->CallObjectMethod(env, this->vpn_service, method_id);
	if (!jencodings || androidjni_exception_occurred(env))
	{
		goto failed;
	}
	list = convert_array_of_byte_arrays(env, jencodings);
	androidjni_detach_thread();
	return list;

failed:
	androidjni_exception_occurred(env);
	androidjni_detach_thread();
	return NULL;
*/
	return NULL;
}

METHOD(charonservice_t, get_user_key, private_key_t*,
	private_charonservice_t *this, public_key_t *pubkey)
{
	DBG1(DBG_DMN, "get_user_key invoked");
/*
	JNIEnv *env;
	jmethodID method_id;
	private_key_t *key;
	jobject jkey;

	androidjni_attach_thread(&env);

	method_id = (*env)->GetMethodID(env,
						android_charonvpnservice_class,
						"getUserKey", "()Ljava/security/PrivateKey;");
	if (!method_id)
	{
		goto failed;
	}
	jkey = (*env)->CallObjectMethod(env, this->vpn_service, method_id);
	if (!jkey || androidjni_exception_occurred(env))
	{
		goto failed;
	}
	key = android_private_key_create(jkey, pubkey);
	androidjni_detach_thread();
	return key;

failed:
	DESTROY_IF(pubkey);
	androidjni_exception_occurred(env);
	androidjni_detach_thread();
	return NULL;
*/
	return NULL;
}

METHOD(charonservice_t, get_vpnservice_builder, vpnservice_builder_t*,
	private_charonservice_t *this)
{
	return this->builder;
}

/*
METHOD(charonservice_t, get_network_manager, network_manager_t*,
	private_charonservice_t *this)
{
	return NULL; //this->network_manager;
}
*/

/**
 * Initiate a new connection
 *
 * @param gateway			gateway address (gets owned)
 * @param username			username (gets owned)
 * @param password			password (gets owned)
 */
void initiateCharon(char *type, char *gateway, char *username, char *password)
{
	private_charonservice_t *this = (private_charonservice_t*)charonservice;
	this->builder->update_status(this->builder, "CONNECTING");
	this->creds->clear(this->creds);
	DESTROY_IF(this->service);
	this->service = android_service_create(this->creds, type, gateway,
										   username, password);

}

/**
 * Initialize/deinitialize Android backend
 */
static bool charonservice_register(plugin_t *plugin, plugin_feature_t *feature,
								   bool reg, void *data)
{
	private_charonservice_t *this = (private_charonservice_t*)charonservice;
	if (reg)
	{
		this->net_handler = android_net_create();
		lib->credmgr->add_set(lib->credmgr, &this->creds->set);
		charon->attributes->add_handler(charon->attributes,
										&this->attr->handler);
	}
	else
	{
		this->net_handler->destroy(this->net_handler);
		lib->credmgr->remove_set(lib->credmgr, &this->creds->set);
		charon->attributes->remove_handler(charon->attributes,
										   &this->attr->handler);
		if (this->service)
		{
			this->service->destroy(this->service);
			this->service = NULL;
		}
	}
	return TRUE;
}

/**
 * Set strongswan.conf options
 */
static void set_options(char *logfile)
{
	lib->settings->set_int(lib->settings,
					"charon.plugins.android_log.loglevel", ANDROID_DEBUG_LEVEL);
	/* setup file logger */
	lib->settings->set_str(lib->settings,
					"charon.filelog.%s.time_format", "%b %e %T", logfile);
	lib->settings->set_bool(lib->settings,
					"charon.filelog.%s.append", FALSE, logfile);
	lib->settings->set_bool(lib->settings,
					"charon.filelog.%s.flush_line", TRUE, logfile);
	lib->settings->set_int(lib->settings,
					"charon.filelog.%s.default", ANDROID_DEBUG_LEVEL, logfile);

	lib->settings->set_int(lib->settings,
					"charon.retransmit_tries", ANDROID_RETRASNMIT_TRIES);
	lib->settings->set_double(lib->settings,
					"charon.retransmit_timeout", ANDROID_RETRANSMIT_TIMEOUT);
	lib->settings->set_double(lib->settings,
					"charon.retransmit_base", ANDROID_RETRANSMIT_BASE);
	lib->settings->set_int(lib->settings,
					"charon.fragment_size", ANDROID_FRAGMENT_SIZE);
	lib->settings->set_bool(lib->settings,
					"charon.close_ike_on_child_failure", TRUE);
	/* setting the source address breaks the VpnService.protect() function which
	 * uses SO_BINDTODEVICE internally.  the addresses provided to the kernel as
	 * auxiliary data have precedence over this option causing a routing loop if
	 * the gateway is contained in the VPN routes.  alternatively, providing an
	 * explicit device (in addition or instead of the source address) in the
	 * auxiliary data would also work, but we currently don't have that
	 * information */
	lib->settings->set_bool(lib->settings,
					"charon.plugins.socket-default.set_source", FALSE);
	/* the Linux kernel does currently not support UDP encaspulation for IPv6
	 * so lets disable IPv6 for now to avoid issues with dual-stack gateways */
	lib->settings->set_bool(lib->settings,
					"charon.plugins.socket-default.use_ipv6", FALSE);
	/* don't install virtual IPs via kernel-netlink */
	lib->settings->set_bool(lib->settings,
					"charon.install_virtual_ip", FALSE);
	/* kernel-netlink should not trigger roam events, we use Android's
	 * ConnectivityManager for that, much less noise */
	lib->settings->set_bool(lib->settings,
					"charon.plugins.kernel-netlink.roam_events", FALSE);
	/* ignore tun devices (it's mostly tun0 but it may already be taken, ignore
	 * some others too), also ignore lo as a default route points to it when
	 * no connectivity is available */
	lib->settings->set_str(lib->settings,
					"charon.interfaces_ignore", "lo, tun0, tun1, tun2, tun3, "
					"tun4");

#ifdef USE_BYOD
	lib->settings->set_str(lib->settings,
					"charon.plugins.eap-tnc.protocol", "tnccs-2.0");
	lib->settings->set_int(lib->settings,
					"charon.plugins.eap-ttls.max_message_count", 0);
	lib->settings->set_bool(lib->settings,
					"android.imc.send_os_info", TRUE);
	lib->settings->set_str(lib->settings,
					"libtnccs.tnc_config", "");
#endif
}

void send_counters(vpnservice_builder_t *builder)
{
	enumerator_t *isas, *csas;
	ike_sa_t *ike_sa;
	child_sa_t *child;
	time_t t;
	u_int64_t bytes, packets;
	u_int64_t bytes_in = 0;
	u_int64_t bytes_out = 0;

	isas = charon->controller->create_ike_sa_enumerator(charon->controller, TRUE);
	while (isas->enumerate(isas, &ike_sa))
	{
		csas = ike_sa->create_child_sa_enumerator(ike_sa);
		while (csas->enumerate(csas, &child))
		{
			if (child->get_state(child) == CHILD_INSTALLED ||
				child->get_state(child) == CHILD_REKEYING ||
				child->get_state(child) == CHILD_REKEYED)
			{
					child->get_usestats(child, TRUE,  &t, &bytes, &packets);
					bytes_in += bytes;
					child->get_usestats(child, FALSE, &t, &bytes, &packets);
					bytes_out += bytes;
			}
		}
		csas->destroy(csas);
	}
	isas->destroy(isas);

  DBG1(DBG_LIB, "Bytes-in %u Bytes out %u", bytes_in, bytes_out);

	builder->send_counters(builder, bytes_in, bytes_out);


}


void *byte_counters(void *data)
{

		vpnservice_builder_t *builder = (vpnservice_builder_t*)data;
		DBG1(DBG_LIB, "Checking counters thread started");
		for(;;)
		{
			DBG1(DBG_LIB, "Checking counters");
			pthread_mutex_lock(&connected_lock);
			bool connected_now = connected;
			if (terminate_counter_thread) {
					pthread_mutex_unlock(&connected_lock);
					break;
			}
			pthread_mutex_unlock(&connected_lock);
			DBG1(DBG_LIB, "Connected=%u", connected_now);
				if (connected_now) {
						send_counters(builder);
				}
				sleep(5);
		}

}

/**
 * Initialize the charonservice object
 */
//static void charonservice_init(JNIEnv *env, jobject service, jobject builder, jboolean byod)
static void charonservice_init(vpnservice_builder_t *builder, bool byod)
{
	private_charonservice_t *this;
	static plugin_feature_t features[] = {
		PLUGIN_CALLBACK(kernel_ipsec_register, kernel_android_ipsec_create),
			PLUGIN_PROVIDE(CUSTOM, "kernel-ipsec"),
		PLUGIN_CALLBACK(charonservice_register, NULL),
			PLUGIN_PROVIDE(CUSTOM, "android-backend"),
				PLUGIN_DEPENDS(CUSTOM, "libcharon"),
	};

	INIT(this,
		.public = {
			.update_status = _update_status,
			.update_imc_state = _update_imc_state,
			.add_remediation_instr = _add_remediation_instr,
			.bypass_socket = _bypass_socket,
			.get_trusted_certificates = _get_trusted_certificates,
			.get_user_certificate = _get_user_certificate,
			.get_user_key = _get_user_key,
			.get_vpnservice_builder = _get_vpnservice_builder,
			.check_and_update_status = _check_and_update_status,
			//.get_network_manager = _get_network_manager,
		},
		.attr = android_attr_create(),
		.creds = android_creds_create(),
		.builder = builder,
		//.network_manager = network_manager_create(service),
		.sockets = linked_list_create(),
		//.vpn_service = (*env)->NewGlobalRef(env, service),
	);
	terminate_counter_thread = FALSE;
	pthread_t counter_thread;

	pthread_create(&counter_thread, NULL, byte_counters, builder);
	charonservice = &this->public;

	lib->plugins->add_static_features(lib->plugins, "androidbridge", features,
									  countof(features), TRUE, NULL, NULL);

#ifdef USE_BYOD
	if (byod)
	{
		plugin_feature_t byod_features[] = {
			PLUGIN_CALLBACK(imc_android_register, NULL),//this->vpn_service),
				PLUGIN_PROVIDE(CUSTOM, "android-imc"),
					PLUGIN_DEPENDS(CUSTOM, "android-backend"),
					PLUGIN_DEPENDS(CUSTOM, "imc-manager"),
		};

		lib->plugins->add_static_features(lib->plugins, "android-byod",
					byod_features, countof(byod_features), TRUE, NULL, NULL);
	}
#endif
}

/**
 * Deinitialize the charonservice object
 */
static void charonservice_deinit()
{
	private_charonservice_t *this = (private_charonservice_t*)charonservice;

	//this->network_manager->destroy(this->network_manager);
	this->sockets->destroy(this->sockets);
	this->builder->destroy(this->builder);
	this->creds->destroy(this->creds);
	this->attr->destroy(this->attr);

	pthread_mutex_lock(&connected_lock);
	terminate_counter_thread = TRUE;
	pthread_mutex_unlock(&connected_lock);

	//(*env)->DeleteGlobalRef(env, this->vpn_service);
	free(this);
	charonservice = NULL;
}

/**
 * Handle SIGSEGV/SIGILL signals raised by threads
 */
static void segv_handler(int signal)
{
	dbg_android(DBG_DMN, 1, "thread %u received %d", thread_current_id(),
				signal);
	exit(1);
}

/**
 * Initialize charon and the libraries via JNI
 */
//JNI_METHOD(CharonVpnService, initializeCharon, jboolean,
//	jobject builder, jstring jlogfile, jboolean byod)
bool initializeCharon(char* logfile, vpnservice_builder_t *builder, bool byod)
{
	struct sigaction action;
	struct utsname utsname;
	char *plugins;

	/* logging for library during initialization, as we have no bus yet */
	//dbg = dbg_android;

	/* initialize library */
	if (!library_init(NULL, "charon"))
	{
		library_deinit();
		return FALSE;
	}

	/* set options before initializing other libraries that might read them */
	set_options(logfile);
	//free(logfile);

	if (!libhydra_init())
	{
		libhydra_deinit();
		library_deinit();
		return FALSE;
	}

	if (!libipsec_init())
	{
		libipsec_deinit();
		libhydra_deinit();
		library_deinit();
		return FALSE;
	}

	if (!libcharon_init())
	{
		libcharon_deinit();
		libipsec_deinit();
		libhydra_deinit();
		library_deinit();
		return FALSE;
	}

	charon->load_loggers(charon, NULL, FALSE);

	//charonservice_init(env, this, builder, byod);

	charonservice_init(builder, byod);

	if (uname(&utsname) != 0)
	{
		memset(&utsname, 0, sizeof(utsname));
	}
	DBG1(DBG_DMN, "Starting IKE charon daemon (strongSwan "VERSION", %s %s, %s)",
		  utsname.sysname, utsname.release, utsname.machine);

#ifdef PLUGINS_BYOD
	if (byod)
	{
		plugins = PLUGINS " " PLUGINS_BYOD;
	}
	else
#endif
	{
		plugins = PLUGINS;
	}

	if (!charon->initialize(charon, plugins))
	{
		libcharon_deinit();
		charonservice_deinit();
		libipsec_deinit();
		libhydra_deinit();
		library_deinit();
		return FALSE;
	}
	DBG1(DBG_DMN, "initialization completed");
	lib->plugins->status(lib->plugins, LEVEL_CTRL);

	/* add handler for SEGV and ILL etc. */
	action.sa_handler = segv_handler;
	action.sa_flags = 0;
	sigemptyset(&action.sa_mask);
	sigaction(SIGSEGV, &action, NULL);
	sigaction(SIGILL, &action, NULL);
	sigaction(SIGBUS, &action, NULL);
	action.sa_handler = SIG_IGN;
	sigaction(SIGPIPE, &action, NULL);

	/* start daemon (i.e. the threads in the thread-pool) */
	charon->start(charon);
	return TRUE;
}

/**
 * Deinitialize charon and all libraries
 */
//JNI_METHOD(CharonVpnService, deinitializeCharon, void)
void deinitializeCharon()
{
	/* deinitialize charon before we destroy our own objects */
	libcharon_deinit();
	charonservice_deinit();
	libipsec_deinit();
	libhydra_deinit();
	library_deinit();
}

/**
 * Initiate SA
 */
/*
JNI_METHOD(CharonVpnService, initiate, void, jstring jtype, jstring jgateway, jstring jusername, jstring jpassword)
{
	char *type, *gateway, *username, *password;

	type = androidjni_convert_jstring(env, jtype);
	gateway = androidjni_convert_jstring(env, jgateway);
	username = androidjni_convert_jstring(env, jusername);
	password = androidjni_convert_jstring(env, jpassword);

	initiate(type, gateway, username, password);
}
*/
