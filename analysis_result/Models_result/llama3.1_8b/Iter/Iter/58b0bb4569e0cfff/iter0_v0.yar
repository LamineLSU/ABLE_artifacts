rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 45 FC 8A D0 E8 ?? ?? ?? ?? 83 C4 ?? }
        $pattern1 = { 6A 01 5A 8B CE E8 ?? ?? ?? ?? 85 C0 }
        $pattern2 = { 53 B9 FF FF FF FF F3 A5 0F 84 ?? ?? ?? ?? }

    condition:
        any of them
}