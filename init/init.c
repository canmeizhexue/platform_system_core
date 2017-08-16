/*
 * Copyright (C) 2008 The Android Open Source Project
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <ctype.h>
#include <signal.h>
#include <sys/wait.h>
#include <sys/mount.h>
#include <sys/stat.h>
#include <sys/poll.h>
#include <errno.h>
#include <stdarg.h>
#include <mtd/mtd-user.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/un.h>
#include <libgen.h>

#include <cutils/sockets.h>
#include <cutils/iosched_policy.h>
#include <private/android_filesystem_config.h>
#include <termios.h>

#include <sys/system_properties.h>

#include "devices.h"
#include "init.h"
#include "list.h"
#include "log.h"
#include "property_service.h"
#include "bootchart.h"
#include "signal_handler.h"
#include "keychords.h"
#include "init_parser.h"
#include "util.h"
#include "ueventd.h"

static int property_triggers_enabled = 0;

#if BOOTCHART
static int   bootchart_count;
#endif

static char console[32];
static char serialno[32];
static char bootmode[32];
static char baseband[32];
static char carrier[32];
static char bootloader[32];
static char hardware[32];
static unsigned revision = 0;
static char qemu[32];

static struct action *cur_action = NULL;
static struct command *cur_command = NULL;
static struct listnode *command_queue = NULL;
//通知服务的状态，
void notify_service_state(const char *name, const char *state)
{
    char pname[PROP_NAME_MAX];
    int len = strlen(name);
    if ((len + 10) > PROP_NAME_MAX)
        return;
    snprintf(pname, sizeof(pname), "init.svc.%s", name);
    property_set(pname, state);
}

static int have_console;
static char *console_name = "/dev/console";
static time_t process_needs_restart;

static const char *ENV[32];

/* 添加环境变量，这里只是放到内存，难道不用存到文件之类的吗？
add_environment - add "key=value" to the current environment */
int add_environment(const char *key, const char *val)
{
    int n;
 
    for (n = 0; n < 31; n++) {
        if (!ENV[n]) {
            size_t len = strlen(key) + strlen(val) + 2;
            char *entry = malloc(len);
            snprintf(entry, len, "%s=%s", key, val);
            ENV[n] = entry;
            return 0;
        }
    }

    return 1;
}

static void zap_stdio(void)
{
    int fd;
    fd = open("/dev/null", O_RDWR);
    dup2(fd, 0);
    dup2(fd, 1);
    dup2(fd, 2);
    close(fd);
}

static void open_console()
{
    int fd;
    if ((fd = open(console_name, O_RDWR)) < 0) {
        fd = open("/dev/null", O_RDWR);
    }
    dup2(fd, 0);
    dup2(fd, 1);
    dup2(fd, 2);
    close(fd);
}
//发布socket，
static void publish_socket(const char *name, int fd)
{
    char key[64] = ANDROID_SOCKET_ENV_PREFIX;
    char val[64];

    strlcpy(key + sizeof(ANDROID_SOCKET_ENV_PREFIX) - 1,
            name,
            sizeof(key) - sizeof(ANDROID_SOCKET_ENV_PREFIX));
    snprintf(val, sizeof(val), "%d", fd);
    add_environment(key, val);

    /* make sure we don't close-on-exec */
    fcntl(fd, F_SETFD, 0);
}
//启动服务，这个里面会创建一个子进程来运行指定的服务，
void service_start(struct service *svc, const char *dynamic_args)
{
    struct stat s;
    pid_t pid;
    int needs_console;
    int n;

        /* starting a service removes it from the disabled
         * state and immediately takes it out of the restarting
         * state if it was in there
         */
    svc->flags &= (~(SVC_DISABLED|SVC_RESTARTING));
    svc->time_started = 0;
    
        /* running processes require no additional work -- if
         * they're in the process of exiting, we've ensured
         * that they will immediately restart on exit, unless
         * they are ONESHOT
         */
    if (svc->flags & SVC_RUNNING) {
        return;
    }

    needs_console = (svc->flags & SVC_CONSOLE) ? 1 : 0;
    if (needs_console && (!have_console)) {
        ERROR("service '%s' requires console\n", svc->name);
        svc->flags |= SVC_DISABLED;
        return;
    }

    if (stat(svc->args[0], &s) != 0) {
        ERROR("cannot find '%s', disabling '%s'\n", svc->args[0], svc->name);
        svc->flags |= SVC_DISABLED;
        return;
    }

    if ((!(svc->flags & SVC_ONESHOT)) && dynamic_args) {
        ERROR("service '%s' must be one-shot to use dynamic args, disabling\n",
               svc->args[0]);
        svc->flags |= SVC_DISABLED;
        return;
    }

    NOTICE("starting '%s'\n", svc->name);
		//可以看到这里创建了一个新的进程啦，，，，，，，
    pid = fork();
		//fork会返回俩次，返回值为0时是在新创建的子进程中，返回值大于0时，是在当前进程（相对于新建的进程来说，是父进程，返回值是新建进程的进程id）
    if (pid == 0) {
    	//运行在新创建的子进程中，
        struct socketinfo *si; //应该是静态的用来描述socket的，
        struct svcenvinfo *ei;
        char tmp[32];
        int fd, sz;

        if (properties_inited()) {
            get_property_workspace(&fd, &sz);
            sprintf(tmp, "%d,%d", dup(fd), sz);
            add_environment("ANDROID_PROPERTY_WORKSPACE", tmp);
        }
				//处理环境变量，
        for (ei = svc->envvars; ei; ei = ei->next)
            add_environment(ei->name, ei->value);
				
				
				//处理socket，
        for (si = svc->sockets; si; si = si->next) {
            int socket_type = (
                    !strcmp(si->type, "stream") ? SOCK_STREAM :
                        (!strcmp(si->type, "dgram") ? SOCK_DGRAM : SOCK_SEQPACKET));
                        	
            //创建socket，
            int s = create_socket(si->name, socket_type,
                                  si->perm, si->uid, si->gid);
            if (s >= 0) {
            	//socket创建成功后，发布socket，
                publish_socket(si->name, s);
            }
        }

        if (svc->ioprio_class != IoSchedClass_NONE) {
            if (android_set_ioprio(getpid(), svc->ioprio_class, svc->ioprio_pri)) {
                ERROR("Failed to set pid %d ioprio = %d,%d: %s\n",
                      getpid(), svc->ioprio_class, svc->ioprio_pri, strerror(errno));
            }
        }

        if (needs_console) {
            setsid();
            open_console();
        } else {
            zap_stdio();
        }

#if 0
        for (n = 0; svc->args[n]; n++) {
            INFO("args[%d] = '%s'\n", n, svc->args[n]);
        }
        for (n = 0; ENV[n]; n++) {
            INFO("env[%d] = '%s'\n", n, ENV[n]);
        }
#endif

        setpgid(0, getpid());
		
		
		//设置请求的一些信息，
    /* as requested, set our gid, supplemental gids, and uid */
        if (svc->gid) {
            setgid(svc->gid);
        }
        if (svc->nr_supp_gids) {
            setgroups(svc->nr_supp_gids, svc->supp_gids);
        }
        if (svc->uid) {
            setuid(svc->uid);
        }
				//进程启动的准备工作做好了，现在开始执行入口点的代码啦，，，
        if (!dynamic_args) {
        		
            if (execve(svc->args[0], (char**) svc->args, (char**) ENV) < 0) {
                ERROR("cannot execve('%s'): %s\n", svc->args[0], strerror(errno));
            }
        } else {
            char *arg_ptrs[INIT_PARSER_MAXARGS+1];
            int arg_idx = svc->nargs;
            char *tmp = strdup(dynamic_args);
            char *next = tmp;
            char *bword;

            /* Copy the static arguments */
            memcpy(arg_ptrs, svc->args, (svc->nargs * sizeof(char *)));

            while((bword = strsep(&next, " "))) {
                arg_ptrs[arg_idx++] = bword;
                if (arg_idx == INIT_PARSER_MAXARGS)
                    break;
            }
            arg_ptrs[arg_idx] = '\0';
            execve(svc->args[0], (char**) arg_ptrs, (char**) ENV);
        }
        //子进程是否不应该到达这里啊，
        _exit(127);
    }

    if (pid < 0) {
        ERROR("failed to start '%s'\n", svc->name);
        svc->pid = 0;
        return;
    }

    svc->time_started = gettime();
    svc->pid = pid;//新建进程的进程id，
    svc->flags |= SVC_RUNNING;//服务的状态标记，正在运行

    if (properties_inited())
        notify_service_state(svc->name, "running");//通知指定的服务的状态，
}
//停止服务，这里会杀死服务所在进程，
void service_stop(struct service *svc)
{
        /* we are no longer running, nor should we
         * attempt to restart
         */
    svc->flags &= (~(SVC_RUNNING|SVC_RESTARTING));

        /* if the service has not yet started, prevent
         * it from auto-starting with its class
         */
    svc->flags |= SVC_DISABLED;

    if (svc->pid) {
        NOTICE("service '%s' is being killed\n", svc->name);
        
        
        //杀死进程，，，
        kill(-svc->pid, SIGTERM);
        notify_service_state(svc->name, "stopping");
    } else {
        notify_service_state(svc->name, "stopped");
    }
}

void property_changed(const char *name, const char *value)
{
    if (property_triggers_enabled)
        queue_property_triggers(name, value);
}
//如果需要的话，重新启动service
static void restart_service_if_needed(struct service *svc)
{
    time_t next_start_time = svc->time_started + 5;

    if (next_start_time <= gettime()) {
        svc->flags &= (~SVC_RESTARTING);
        service_start(svc, NULL);
        return;
    }

    if ((next_start_time < process_needs_restart) ||
        (process_needs_restart == 0)) {
        process_needs_restart = next_start_time;
    }
}
//重启相关服务的进程，
static void restart_processes()
{
    process_needs_restart = 0;
    service_for_each_flags(SVC_RESTARTING,
                           restart_service_if_needed);
}
//找到对应的service结构体，然后启动service
static void msg_start(const char *name)
{
    struct service *svc;
    char *tmp = NULL;
    char *args = NULL;
		//找到对应的service结构体，
    if (!strchr(name, ':'))
        svc = service_find_by_name(name);
    else {
        tmp = strdup(name);
        args = strchr(tmp, ':');
        *args = '\0';
        args++;

        svc = service_find_by_name(tmp);
    }
    
    if (svc) {
    		//启动服务，
        service_start(svc, args);
    } else {
        ERROR("no such service '%s'\n", name);
    }
    if (tmp)
        free(tmp);
}

static void msg_stop(const char *name)
{
    struct service *svc = service_find_by_name(name);

    if (svc) {
        service_stop(svc);
    } else {
        ERROR("no such service '%s'\n", name);
    }
}
//处理控制信息，启动服务，停止服务，
void handle_control_message(const char *msg, const char *arg)
{
    if (!strcmp(msg,"start")) {
        msg_start(arg);
    } else if (!strcmp(msg,"stop")) {
        msg_stop(arg);
    } else {
        ERROR("unknown control msg '%s'\n", msg);
    }
}

static void import_kernel_nv(char *name, int in_qemu)
{
    char *value = strchr(name, '=');

    if (value == 0) return;
    *value++ = 0;
    if (*name == 0) return;

    if (!in_qemu)
    {
        /* on a real device, white-list the kernel options */
        if (!strcmp(name,"qemu")) {
            strlcpy(qemu, value, sizeof(qemu));
        } else if (!strcmp(name,"androidboot.console")) {
            strlcpy(console, value, sizeof(console));
        } else if (!strcmp(name,"androidboot.mode")) {
            strlcpy(bootmode, value, sizeof(bootmode));
        } else if (!strcmp(name,"androidboot.serialno")) {
            strlcpy(serialno, value, sizeof(serialno));
        } else if (!strcmp(name,"androidboot.baseband")) {
            strlcpy(baseband, value, sizeof(baseband));
        } else if (!strcmp(name,"androidboot.carrier")) {
            strlcpy(carrier, value, sizeof(carrier));
        } else if (!strcmp(name,"androidboot.bootloader")) {
            strlcpy(bootloader, value, sizeof(bootloader));
        } else if (!strcmp(name,"androidboot.hardware")) {
            strlcpy(hardware, value, sizeof(hardware));
        }
    } else {
        /* in the emulator, export any kernel option with the
         * ro.kernel. prefix */
        char  buff[32];
        int   len = snprintf( buff, sizeof(buff), "ro.kernel.%s", name );
        if (len < (int)sizeof(buff)) {
            property_set( buff, value );
        }
    }
}

static void import_kernel_cmdline(int in_qemu)
{
    char cmdline[1024];
    char *ptr;
    int fd;

    fd = open("/proc/cmdline", O_RDONLY);
    if (fd >= 0) {
        int n = read(fd, cmdline, 1023);
        if (n < 0) n = 0;

        /* get rid of trailing newline, it happens */
        if (n > 0 && cmdline[n-1] == '\n') n--;

        cmdline[n] = 0;
        close(fd);
    } else {
        cmdline[0] = 0;
    }

    ptr = cmdline;
    while (ptr && *ptr) {
        char *x = strchr(ptr, ' ');
        if (x != 0) *x++ = 0;
        import_kernel_nv(ptr, in_qemu);
        ptr = x;
    }

        /* don't expose the raw commandline to nonpriv processes */
    chmod("/proc/cmdline", 0440);
}
//获取action的第一个command,
static struct command *get_first_command(struct action *act)
{
    struct listnode *node;
    node = list_head(&act->commands);
    if (!node)
        return NULL;

    return node_to_item(node, struct command, clist);
}
//获取action的cmd之后的command
static struct command *get_next_command(struct action *act, struct command *cmd)
{
    struct listnode *node;
    node = cmd->clist.next;
    if (!node)
        return NULL;
    if (node == &act->commands)
        return NULL;

    return node_to_item(node, struct command, clist);
}
//指定的cmd是否是action的最后一个command
static int is_last_command(struct action *act, struct command *cmd)
{
    return (list_tail(&act->commands) == &cmd->clist);
}
//执行一个command,这个action构成一个链表，每个aciton里面都有一个command链条，
void execute_one_command(void)
{
    int ret;

    if (!cur_action || !cur_command || is_last_command(cur_action, cur_command)) {
        cur_action = action_remove_queue_head();
        cur_command = NULL;
        if (!cur_action)
            return;
        INFO("processing action %p (%s)\n", cur_action, cur_action->name);
        cur_command = get_first_command(cur_action);
    } else {
        cur_command = get_next_command(cur_action, cur_command);
    }

    if (!cur_command)
        return;

    ret = cur_command->func(cur_command->nargs, cur_command->args);
    INFO("command '%s' r=%d\n", cur_command->args[0], ret);
}

static int wait_for_coldboot_done_action(int nargs, char **args)
{
    int ret;
    INFO("wait for %s\n", coldboot_done);
    ret = wait_for_file(coldboot_done, COMMAND_RETRY_TIMEOUT);
    if (ret)
        ERROR("Timed out waiting for %s\n", coldboot_done);
    return ret;
}

static int property_init_action(int nargs, char **args)
{
    INFO("property init\n");
    property_init();
    return 0;
}

static int keychord_init_action(int nargs, char **args)
{
    keychord_init();
    return 0;
}

static int console_init_action(int nargs, char **args)
{
    int fd;
    char tmp[PROP_VALUE_MAX];

    if (console[0]) {
        snprintf(tmp, sizeof(tmp), "/dev/%s", console);
        console_name = strdup(tmp);
    }

    fd = open(console_name, O_RDWR);
    if (fd >= 0)
        have_console = 1;
    close(fd);

    if( load_565rle_image(INIT_IMAGE_FILE) ) {
        fd = open("/dev/tty0", O_WRONLY);
        if (fd >= 0) {
            const char *msg;
                msg = "\n"
            "\n"
            "\n"
            "\n"
            "\n"
            "\n"
            "\n"  // console is 40 cols x 30 lines
            "\n"
            "\n"
            "\n"
            "\n"
            "\n"
            "\n"
            "\n"
            "             A N D R O I D ";
            write(fd, msg, strlen(msg));
            close(fd);
        }
    }
    return 0;
}

static int set_init_properties_action(int nargs, char **args)
{
    char tmp[PROP_VALUE_MAX];

    if (qemu[0])
        import_kernel_cmdline(1);

    if (!strcmp(bootmode,"factory"))
        property_set("ro.factorytest", "1");
    else if (!strcmp(bootmode,"factory2"))
        property_set("ro.factorytest", "2");
    else
        property_set("ro.factorytest", "0");

    property_set("ro.serialno", serialno[0] ? serialno : "");
    property_set("ro.bootmode", bootmode[0] ? bootmode : "unknown");
    property_set("ro.baseband", baseband[0] ? baseband : "unknown");
    property_set("ro.carrier", carrier[0] ? carrier : "unknown");
    property_set("ro.bootloader", bootloader[0] ? bootloader : "unknown");

    property_set("ro.hardware", hardware);
    snprintf(tmp, PROP_VALUE_MAX, "%d", revision);
    property_set("ro.revision", tmp);
    return 0;
}

static int property_service_init_action(int nargs, char **args)
{
    /* read any property files on system or data and
     * fire up the property service.  This must happen
     * after the ro.foo properties are set above so
     * that /data/local.prop cannot interfere with them.
     */
    start_property_service();
    return 0;
}

static int signal_init_action(int nargs, char **args)
{
    signal_init();
    return 0;
}

static int check_startup_action(int nargs, char **args)
{
    /* make sure we actually have all the pieces we need */
    if ((get_property_set_fd() < 0) ||
        (get_signal_fd() < 0)) {
        ERROR("init startup failure\n");
        exit(1);
    }
    return 0;
}

static int queue_property_triggers_action(int nargs, char **args)
{
    queue_all_property_triggers();
    /* enable property triggers */
    property_triggers_enabled = 1;
    return 0;
}
//条件编译，
#if BOOTCHART
static int bootchart_init_action(int nargs, char **args)
{
    bootchart_count = bootchart_init();
    if (bootchart_count < 0) {
        ERROR("bootcharting init failure\n");
    } else if (bootchart_count > 0) {
        NOTICE("bootcharting started (period=%d ms)\n", bootchart_count*BOOTCHART_POLLING_MS);
    } else {
        NOTICE("bootcharting ignored\n");
    }
}
#endif
//入口点
int main(int argc, char **argv)
{
    int fd_count = 0;
    struct pollfd ufds[4];
    char *tmpdev;
    char* debuggable;
    char tmp[32];
    int property_set_fd_init = 0;
    int signal_fd_init = 0;
    int keychord_fd_init = 0;

    if (!strcmp(basename(argv[0]), "ueventd"))
        return ueventd_main(argc, argv);

    /* clear the umask */
    umask(0);

        /* Get the basic filesystem setup we need put
         * together in the initramdisk on / and then we'll
         * let the rc file figure out the rest.
         */
         //创建文件系统的基本目录，
    mkdir("/dev", 0755);
    mkdir("/proc", 0755);
    mkdir("/sys", 0755);

    mount("tmpfs", "/dev", "tmpfs", 0, "mode=0755");
    mkdir("/dev/pts", 0755);
    mkdir("/dev/socket", 0755);
    mount("devpts", "/dev/pts", "devpts", 0, NULL);
    mount("proc", "/proc", "proc", 0, NULL);
    mount("sysfs", "/sys", "sysfs", 0, NULL);

        /* We must have some place other than / to create the
         * device nodes for kmsg and null, otherwise we won't
         * be able to remount / read-only later on.
         * Now that tmpfs is mounted on /dev, we can actually
         * talk to the outside world.
         */
    open_devnull_stdio();
    log_init();//初始化log
    
    INFO("reading config file\n");
    //解析配置文件，
    init_parse_config_file("/init.rc");

    /* pull the kernel commandline and ramdisk properties file in */
    import_kernel_cmdline(0);

    get_hardware_name(hardware, &revision);
    snprintf(tmp, sizeof(tmp), "/init.%s.rc", hardware);
    init_parse_config_file(tmp);

		//将对应触发器的action添加到action_queue的队列尾部，待后续执行，从下面的死循环可以看到这些动作没有发生相应的事件也执行了，或者叫代码主动触发的？
    action_for_each_trigger("early-init", action_add_queue_tail);
		
		//第一个参数是函数指针，第二个参数是触发器的名字，这个地方说明，action有代码构建的，也有在脚本里面构建的，会将action加入到action_queue，后续的死循环里面会调用
    queue_builtin_action(wait_for_coldboot_done_action, "wait_for_coldboot_done");
    queue_builtin_action(property_init_action, "property_init");
    queue_builtin_action(keychord_init_action, "keychord_init");
    queue_builtin_action(console_init_action, "console_init");
    queue_builtin_action(set_init_properties_action, "set_init_properties");

        /* execute all the boot actions to get us started */
        //将对应触发器的action添加到action_queue的队列尾部，待后续执行，
    action_for_each_trigger("init", action_add_queue_tail);
    action_for_each_trigger("early-fs", action_add_queue_tail);
    action_for_each_trigger("fs", action_add_queue_tail);
    action_for_each_trigger("post-fs", action_add_queue_tail);

		//
    queue_builtin_action(property_service_init_action, "property_service_init");
    queue_builtin_action(signal_init_action, "signal_init");
    queue_builtin_action(check_startup_action, "check_startup");

    /* execute all the boot actions to get us started */
    //将对应触发器的action添加到action_queue的队列尾部，待后续执行，
    action_for_each_trigger("early-boot", action_add_queue_tail);
    action_for_each_trigger("boot", action_add_queue_tail);

        /* run all property triggers based on current state of the properties */
    queue_builtin_action(queue_property_triggers_action, "queue_propety_triggers");


#if BOOTCHART
    queue_builtin_action(bootchart_init_action, "bootchart_init");
#endif
		//这个地方是个死循环，从action_queue取出action,然后一次执行一个command,然后通过poll取出一个事件进行处理，如此重复
    for(;;) {
        int nr, i, timeout = -1;
        
				//从action_queue取出action,然后一次执行一个command,逐步执行之前的command啦，
        execute_one_command();
        restart_processes();

        if (!property_set_fd_init && get_property_set_fd() > 0) {
            ufds[fd_count].fd = get_property_set_fd();
            ufds[fd_count].events = POLLIN;
            ufds[fd_count].revents = 0;
            fd_count++;
            property_set_fd_init = 1;
        }
        if (!signal_fd_init && get_signal_fd() > 0) {
            ufds[fd_count].fd = get_signal_fd();
            ufds[fd_count].events = POLLIN;
            ufds[fd_count].revents = 0;
            fd_count++;
            signal_fd_init = 1;
        }
        if (!keychord_fd_init && get_keychord_fd() > 0) {
            ufds[fd_count].fd = get_keychord_fd();
            ufds[fd_count].events = POLLIN;
            ufds[fd_count].revents = 0;
            fd_count++;
            keychord_fd_init = 1;
        }

        if (process_needs_restart) {
            timeout = (process_needs_restart - gettime()) * 1000;
            if (timeout < 0)
                timeout = 0;
        }

        if (!action_queue_empty() || cur_action)
            timeout = 0;

#if BOOTCHART
        if (bootchart_count > 0) {
            if (timeout < 0 || timeout > BOOTCHART_POLLING_MS)
                timeout = BOOTCHART_POLLING_MS;
            if (bootchart_step() < 0 || --bootchart_count == 0) {
                bootchart_finish();
                bootchart_count = 0;
            }
        }
#endif
				//取出事件，然后执行，，这个地方一次可以取出多个事件啦，，
        nr = poll(ufds, fd_count, timeout);
        if (nr <= 0)
            continue;

        for (i = 0; i < fd_count; i++) {
            if (ufds[i].revents == POLLIN) {
                if (ufds[i].fd == get_property_set_fd())
                    handle_property_set_fd();
                else if (ufds[i].fd == get_keychord_fd())
                    handle_keychord();
                else if (ufds[i].fd == get_signal_fd())
                    handle_signal();
            }
        }
    }

    return 0;
}
