rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass over x86-64 check signature"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 7E 8B FC E5 ?? ?? ?? ?? 89 C0 }  // Skips TEST EAX and JZ
        $pattern1 = { 6A ?? 5A ?? 8B CE E8 ?? ?? ?? ?? 83 F4 }  // Direct bypass call
        $pattern2 = { FF ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? C0 }  // Multi-instruction bypass

    condition:
        any of them
}