rule Bypass_Evasion
{
    meta:
        description = "Evasion bypass targeting specific instruction sequences"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { E8 ?? 75 0C ?? ?? }
        $pattern1 = { FF 15 AC B0 41 DC 75 0C ?? ?? }
        $pattern2 = { 6A ?? 5A 8B CE E8 40 C3 ?? ?? }

    condition:
        any of them
}