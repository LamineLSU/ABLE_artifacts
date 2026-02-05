rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { FF 15 54 A0 F6 00 48 83 EC 28 48 8D 0D ?? ?? ?? ?? ?? }
        $pattern1 = { 6A 01 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern2 = { 6A ?? 5A 8B CE E8 ?? ?? ?? ?? }

    condition:
        any of them
}