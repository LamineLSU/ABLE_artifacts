rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 6A 35 6A 00 6A 00 51 50 E8 ?? ?? ?? ?? }  // Push 35h, 0h, 0h, Push EBP, Push EAX, CALL offset -  Pushing multiple zero values and a constant is a common evasion technique.
        $pattern1 = { 8B 16 50 51 FF D2 5E 5D }  // MOV dword ptr [esi], CALL, POP ESI, POP EBP - Indirect call through ESI, followed by stack cleanup.
        $pattern2 = { 8B 45 08 8B 48 10 56 6A 36 6A 00 51 8D B0 ?? ?? ?? ?? } //MOV EAX, dword ptr [ebp+08h], MOV ECX, dword ptr [eax+10h], Push ESI, Push 36h, Push 0h, Push ECX, LEA esi -  Stack frame access followed by pushes and a LEA. This pattern looks like it is manipulating the stack.

    condition:
        any of them
}