#include <stdio.h>

void Method1();
void Method2();

int main()
{
	Method1();
	Method2();

	return 0x1;
}

void Method1()
{
	char msg1[] = "VM Detected !\n";
	char msg2[] = "VM not Detected !\n";
	__asm
	{
		xor eax, eax //EAX=0
		inc eax //EAX=1
		cpuid // Fiziksel makinede 31.bit = 1, sanal makinede 31.bit =0
		bt ecx, 0x1f // CF <- Bit(BitBase,BitOffset) https://www.aldeid.com/wiki/X86-assembly/Instructions/bt
		//jc VM //Jump if carry
		setc al
		cmp al, 0x0
		jz physical
		jmp vm
		physical :
		lea ebx, msg2
			push ebx
			call printf
			pop ebx
			leave
			ret
			vm :
		lea ebx, msg1
			push ebx
			call printf
			pop ebx
			leave
			ret

	}
}

void Method2()
{
	char msg1[] = "VM Detected !";
	char msg2[] = "VM not Detected !";
	__asm
	{
		xor eax,eax
		mov eax,0x40000000
		cpuid
		cmp ecx, 0x4D566572
		je vm
		cmp edx, 0x65726177
		je vm
		jmp physical
		physical :
		lea ebx, msg2
			push ebx
			call printf
			pop ebx
			leave
			ret
			vm :
		lea ebx, msg1
			push ebx
			call printf
			pop ebx
			leave
			ret

	}
}