/*
 * Copyright (C) 2020 Webistics Holdings Ltd.
 * Copyright (C) 2012-2014 Tobias Brunner
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

#include "vpnservice_builder.h"
//#include "android_jni.h"

#include <utils/debug.h>
#include <library.h>
#include "android_exe.h"
#include <pthread.h>


typedef struct private_vpnservice_builder_t private_vpnservice_builder_t;

/**
 * private data of vpnservice_builder
 */
struct private_vpnservice_builder_t {

	/**
	 * public interface
	 */
	vpnservice_builder_t public;

	char needok_result[CRED_BUF_LEN];
	int recvFd;
	pthread_cond_t *cond;
	pthread_mutex_t *lock;
	int socket_fd;
};

bool run_command(private_vpnservice_builder_t *this, char* command, char* expected_response)
{
	send_command(this->socket_fd, command);

	for (;;) {
		//DBG1(DBG_LIB, "Waiting for lock...");
		pthread_mutex_lock(this->lock);
		//pthread_cond_wait(this->cond, this->lock);
		if (strcmp(this->needok_result, expected_response) == 0) {
				pthread_mutex_unlock(this->lock);
				return TRUE;
		}
		pthread_mutex_unlock(this->lock);
	}

	return FALSE;
}

METHOD(vpnservice_builder_t, protect_socket, bool,
	private_vpnservice_builder_t *this, int fd)
{
		send_command_with_fd(this->socket_fd, ">NEED-OK:Need 'PROTECTFD' confirmation MSG:protect_fd_nonlocal\n", fd);
		for (;;) {
			//DBG1(DBG_LIB, "Waiting for lock...");
			pthread_mutex_lock(this->lock);
			//pthread_cond_wait(this->cond, this->lock);
			if (strcmp(this->needok_result, "PROTECTFD") == 0) {
					pthread_mutex_unlock(this->lock);
					return TRUE;
			}
			pthread_mutex_unlock(this->lock);
		}

		return FALSE;
}
METHOD(vpnservice_builder_t, update_status, bool, private_vpnservice_builder_t *this, char* status)
{
	char command[255];
	memset(command, 0, 255);
	snprintf(command, 255, " >STATE:%u,%s,,,,,,\n", (unsigned long)time(NULL), status);
	DBG1(DBG_LIB, "Builder: command constructed %s", command);
  send_command(this->socket_fd, command);

	return TRUE;
}

METHOD(vpnservice_builder_t, add_address, bool,
	private_vpnservice_builder_t *this, host_t *addr, int mtu)
{
	DBG1(DBG_LIB, "Builder: add address invoked");
	int prefix = addr->get_family(addr) == AF_INET ? 32 : 128;

	host_t *netmask = host_create_netmask(addr->get_family(addr), prefix);

	char command[255];

	memset(command, 0, 255);

	snprintf(command, 255, ">NEED-OK:Need 'IFCONFIG' confirmation MSG:%+H %+H %u\n", addr, netmask, mtu);

	DBG1(DBG_LIB, "Builder: command constructed %s", command);
	netmask->destroy(netmask);

	return run_command(this, command, "IFCONFIG");

/*
	JNIEnv *env;
	jmethodID method_id;
	jstring str;
	char buf[INET6_ADDRSTRLEN];
	int prefix;

	androidjni_attach_thread(&env);

	DBG2(DBG_LIB, "builder: adding interface address %H", addr);

	prefix = addr->get_family(addr) == AF_INET ? 32 : 128;
	if (snprintf(buf, sizeof(buf), "%H", addr) >= sizeof(buf))
	{
		goto failed;
	}

	method_id = (*env)->GetMethodID(env, android_charonvpnservice_builder_class,
									"addAddress", "(Ljava/lang/String;I)Z");
	if (!method_id)
	{
		goto failed;
	}
	str = (*env)->NewStringUTF(env, buf);
	if (!str)
	{
		goto failed;
	}
	if (!(*env)->CallBooleanMethod(env, this->builder, method_id, str, prefix))
	{
		goto failed;
	}
	androidjni_detach_thread();
	return TRUE;

failed:
	DBG1(DBG_LIB, "builder: failed to add address");
	androidjni_exception_occurred(env);
	androidjni_detach_thread();
	return FALSE;
*/
}

METHOD(vpnservice_builder_t, set_mtu, bool,
	private_vpnservice_builder_t *this, int mtu)
{
	return FALSE;
/*
	JNIEnv *env;
	jmethodID method_id;

	androidjni_attach_thread(&env);

	DBG2(DBG_LIB, "builder: setting MTU to %d", mtu);

	method_id = (*env)->GetMethodID(env, android_charonvpnservice_builder_class,
									"setMtu", "(I)Z");
	if (!method_id)
	{
		goto failed;
	}
	if (!(*env)->CallBooleanMethod(env, this->builder, method_id, mtu))
	{
		goto failed;
	}
	androidjni_detach_thread();
	return TRUE;

failed:
	DBG1(DBG_LIB, "builder: failed to set MTU");
	androidjni_exception_occurred(env);
	androidjni_detach_thread();
	return FALSE;
*/
}

METHOD(vpnservice_builder_t, add_route, bool,
	private_vpnservice_builder_t *this, host_t *net, int prefix)
{
	DBG1(DBG_LIB, "Builder: add route invoked with network %H+ and prefix %u" , net, prefix);
	host_t *netmask = host_create_netmask(net->get_family(net), prefix);

	char command[255];

	memset(command, 0, 255);

	snprintf(command, 255, ">NEED-OK:Need 'ROUTE' confirmation MSG:%+H %+H\n", net, netmask);

	DBG1(DBG_LIB, "Builder: command constructed %s", command);

	netmask->destroy(netmask);

	return run_command(this, command, "ROUTE");
/*
	JNIEnv *env;
	jmethodID method_id;
	jstring str;
	char buf[INET6_ADDRSTRLEN];

	androidjni_attach_thread(&env);

	DBG2(DBG_LIB, "builder: adding route %+H/%d", net, prefix);

	if (snprintf(buf, sizeof(buf), "%+H", net) >= sizeof(buf))
	{
		goto failed;
	}

	method_id = (*env)->GetMethodID(env, android_charonvpnservice_builder_class,
									"addRoute", "(Ljava/lang/String;I)Z");
	if (!method_id)
	{
		goto failed;
	}
	str = (*env)->NewStringUTF(env, buf);
	if (!str)
	{
		goto failed;
	}
	if (!(*env)->CallBooleanMethod(env, this->builder, method_id, str, prefix))
	{
		goto failed;
	}
	androidjni_detach_thread();
	return TRUE;

failed:
	DBG1(DBG_LIB, "builder: failed to add route");
	androidjni_exception_occurred(env);
	androidjni_detach_thread();
	return FALSE;
*/
}

METHOD(vpnservice_builder_t, add_dns, bool,
	private_vpnservice_builder_t *this, host_t *dns)
{
	DBG1(DBG_LIB, "Builder: add DNS invoked");

	char command[255];
	memset(command, 0, 255);
	snprintf(command, 255, ">NEED-OK:Need 'DNSSERVER' confirmation MSG:%+H\n", dns);
	return run_command(this, command, "DNSSERVER");
/*
	JNIEnv *env;
	jmethodID method_id;
	jstring str;
	char buf[INET6_ADDRSTRLEN];

	androidjni_attach_thread(&env);

	DBG2(DBG_LIB, "builder: adding DNS server %H", dns);

	if (snprintf(buf, sizeof(buf), "%H", dns) >= sizeof(buf))
	{
		goto failed;
	}

	method_id = (*env)->GetMethodID(env, android_charonvpnservice_builder_class,
									"addDnsServer", "(Ljava/lang/String;)Z");
	if (!method_id)
	{
		goto failed;
	}
	str = (*env)->NewStringUTF(env, buf);
	if (!str)
	{
		goto failed;
	}
	if (!(*env)->CallBooleanMethod(env, this->builder, method_id, str))
	{
		goto failed;
	}
	androidjni_detach_thread();
	return TRUE;

failed:
	DBG1(DBG_LIB, "builder: failed to add DNS server");
	androidjni_exception_occurred(env);
	androidjni_detach_thread();
	return FALSE;
*/
}

/**
 * Establish or reestablish the TUN device
 */
static int establish_internal(private_vpnservice_builder_t *this, char *method)
{
	if (run_command(this, ">NEED-OK:Need 'OPENTUN' confirmation MSG:tun\n", "OPENTUN")) {
			return this->recvFd;
	} else {
			return -1;
	}
/*
	JNIEnv *env;
	jmethodID method_id;
	int fd;

	androidjni_attach_thread(&env);

	DBG2(DBG_LIB, "builder: building TUN device");

	method_id = (*env)->GetMethodID(env, android_charonvpnservice_builder_class,
									method, "()I");
	if (!method_id)
	{
		goto failed;
	}
	fd = (*env)->CallIntMethod(env, this->builder, method_id);
	if (fd == -1)
	{
		goto failed;
	}
	androidjni_detach_thread();
	return fd;

failed:
	DBG1(DBG_LIB, "builder: failed to build TUN device");
	androidjni_exception_occurred(env);
	androidjni_detach_thread();
	return -1;
*/
}

METHOD(vpnservice_builder_t, establish, int,
	private_vpnservice_builder_t *this)
{
	return establish_internal(this, "establish");
}

METHOD(vpnservice_builder_t, establish_no_dns, int,
	private_vpnservice_builder_t *this)
{
	return establish_internal(this, "establishNoDns");
}

METHOD(vpnservice_builder_t, destroy, void,
	private_vpnservice_builder_t *this)
{
	/*
	JNIEnv *env;

	androidjni_attach_thread(&env);
	(*env)->DeleteGlobalRef(env, this->builder);
	androidjni_detach_thread();
*/
	free(this);
}

METHOD(vpnservice_builder_t, set_needok_result, void, private_vpnservice_builder_t *this, char* result, int recvFd)
{
		strcpy(this->needok_result, result);
		this->recvFd = recvFd;
}

METHOD(vpnservice_builder_t, send_counters, void, private_vpnservice_builder_t * this, int bytes_in, int bytes_out)
{
	char command[255];
	memset(command, 0, 255);
	snprintf(command, 255, ">BYTECOUNT:%u,%u\n", bytes_in, bytes_out);
	DBG1(DBG_LIB, "Builder: command constructed %s", command);
  send_command(this->socket_fd, command);
}


vpnservice_builder_t *vpnservice_builder_create(int socket_fd, pthread_cond_t *cond, pthread_mutex_t *lock)
{
	//JNIEnv *env;
	private_vpnservice_builder_t *this;

	INIT(this,
		.public = {
			.add_address = _add_address,
			.add_route = _add_route,
			.add_dns = _add_dns,
			.set_mtu = _set_mtu,
			.establish = _establish,
			.establish_no_dns = _establish_no_dns,
			.destroy = _destroy,
			.set_needok_result = _set_needok_result,
			.protect_socket = _protect_socket,
			.update_status = _update_status,
			.send_counters = _send_counters
		},
		.socket_fd = socket_fd,
		.cond = cond,
		.lock = lock
	);

	//androidjni_attach_thread(&env);
	//this->builder = (*env)->NewGlobalRef(env, builder);
	//androidjni_detach_thread();

	return &this->public;
}
