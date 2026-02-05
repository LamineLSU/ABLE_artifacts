rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 10 ?? ?? ?? ?? FF D0 } // mov eax, dword ptr [ebp+0x10], followed by call
        $pattern1 = { E8 02 FF ?? }             // call with displacement 0x02; context added after instruction
        $pattern2 = { 8B 88 D8 02 00 00 ?? ?? ?? ?? FF FD } // mov ecx, dword ptr [ebp+0x10h], followed by call

    condition:
        any of them
}