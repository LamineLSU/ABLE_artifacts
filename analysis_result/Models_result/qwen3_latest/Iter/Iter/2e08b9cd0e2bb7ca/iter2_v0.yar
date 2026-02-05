rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 83 BD 60 F9 FF FF 01 }  // cmp dword ptr [ebp-000006A0h], 01h
        $pattern1 = { 59 FF 15 ?? ?? ?? ?? }  // pop ecx + call [address]
        $pattern2 = { 6A 00 E8 ?? ?? ?? ?? }  // push 00000000 + call [address]

    condition:
        any of them
}