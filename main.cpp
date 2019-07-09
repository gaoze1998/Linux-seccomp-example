#include <fcntl.h>
#include <seccomp.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <stddef.h>
#include <stdio.h>
#include <unistd.h>

int main(int argc, char* argv[])
{
	/* syscalls_blacklistϵͳ���ú�����
	* ����������clone,fork,vfork,kill,execveat
	*/
	int syscalls_blacklist[] = { SCMP_SYS(clone),
							SCMP_SYS(fork), SCMP_SYS(vfork),
							SCMP_SYS(kill),
#ifdef __NR_execveat
							SCMP_SYS(execveat)
#endif
	};
	
	int syscalls_blacklist_length = sizeof(syscalls_blacklist) / sizeof(int); // ����������

	scmp_filter_ctx ctx; // seccomp������(ʵ�ʾ���void*����,������seccomp_init����)

	ctx = seccomp_init(SCMP_ACT_ALLOW); // ��ʼ��seccomp,�������е���
	if (ctx == NULL)
		goto out;

	//����������Ӻ�����
	for (int i = 0; i < syscalls_blacklist_length; i++) {
		if (seccomp_rule_add(ctx, SCMP_ACT_KILL, syscalls_blacklist[i], 0) != 0) {
			goto out;
		}
	}
	
	//֪ͨ�ں����������
	if (seccomp_load(ctx) < 0)
		goto out;

	fork(); //һ���Ƿ�����, ����Գ���ע�͵������۲����̨�������
	printf("You should not see this!");

out:
	seccomp_release(ctx); //�ͷŹ�����
	return 0;
}