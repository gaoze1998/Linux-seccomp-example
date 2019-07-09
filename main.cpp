#include <fcntl.h>
#include <seccomp.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char* argv[])
{
	/* syscalls_blacklist系统调用黑名单
	* 禁用名单：clone,fork,vfork,kill,execveat
	*/
	int syscalls_blacklist[] = { SCMP_SYS(clone),
							SCMP_SYS(fork), SCMP_SYS(vfork),
							SCMP_SYS(kill),
#ifdef __NR_execveat
							SCMP_SYS(execveat)
#endif
	};
	
	int syscalls_blacklist_length = sizeof(syscalls_blacklist) / sizeof(int); // 黑名单长度

	scmp_filter_ctx ctx; // seccomp过滤器(实际就是void*类型,具体由seccomp_init生成)

	ctx = seccomp_init(SCMP_ACT_ALLOW); // 初始化seccomp,运行所有调用
	if (ctx == NULL)
		goto out;

	//给过滤器添加黑名单
	for (int i = 0; i < syscalls_blacklist_length; i++) {
		if (seccomp_rule_add(ctx, SCMP_ACT_KILL, syscalls_blacklist[i], 0) != 0) {
			goto out;
		}
	}
	
	//通知内核载入过滤器
	if (seccomp_load(ctx) < 0)
		goto out;

	fork(); //一个非法调用, 你可以尝试注释掉它，观察控制台输出区别
	printf("You should not see this!");

out:
	seccomp_release(ctx); //释放过滤器
	return 0;
}