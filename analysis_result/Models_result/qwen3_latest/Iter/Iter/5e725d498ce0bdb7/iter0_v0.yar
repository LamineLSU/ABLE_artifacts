rule MaliciousCodePattern
{
    meta:
        description = "Detects malicious code patterns based on specific opcodes and memory addresses"
        cape_options = "bp0=$a+0,action0=skip,bp1=$b+0,action1=skip,bp2=$c+0,action2=skip,count=0"
    
    strings:
        $a = { 83 C4 14 52 FF D0 }  // add esp, 14h; push edx; call eax
        $b = { 8B 16 50 51 FF D2 }  // mov edx, [esi]; push eax; push ecx; call edx
        $c = { 4D 47 A9 ?? ?? ?? ?? }  // dec ebp; inc edi; test eax, imm32 (with wildcarded immediate)
    
    condition:
        all of them
}