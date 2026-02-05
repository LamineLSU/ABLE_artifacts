rule Bypass_Sample {
    meta:
        description = "Evasion bypass patterns targeting suspicious stack operations"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ??C8FFFF ??15ACB04100 }
        $pattern1 = { 8B EC 55 00 ?? 5A 8B CE E8 ?? }
        $pattern2 = { FF7508 push dword ptr [ebp+08h] pop ebp ?? }