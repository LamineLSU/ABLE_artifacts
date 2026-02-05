rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass patterns targeting specific code paths"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 FD BC 5E 84 ?? ?? ?? ?? A1 03 8B 5A }
        $pattern1 = { 6A 8B 45 ?? 8C 00 74 1A 89 C0 45 74 20 85 }
        $pattern2 = { 6D 8B FF 8E FC 53 FA 8B FE ?? 8B 5A ED }

    condition:
        any of them
}