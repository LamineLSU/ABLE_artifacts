rule Bypass_Sample_Evolved
{
    meta:
        description = "Evasion bypass rule - evolved"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 48 89 74 24 30 FF 15 ?? ?? ?? ?? }  // Call after mov [rsp+30h]
        $pattern1 = { 45 33 C9 BA 00 00 00 C0 }             // xor r9d + mov edx
        $pattern2 = { 48 8B CF FF 15 ?? ?? ?? ?? }          // mov rcx + call

    condition:
        any of them
}