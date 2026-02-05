rule Bypass_Sample
{
    meta:
        description = "Evasion bypass patterns targeting address jumps and register checks"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 8B 25 0F 84 ?? ?? ?? ?? 3A 7E 00 01 } 
        $pattern1 = { FF 15 3C E1 1F 01 59 FF 15 40 E1 1F 01 ?? ?? ?? ?? 6A 5B 8B CE E8 ?? 8B 45 5A ?? ?? ?? ?? 74 12 8D 43 00 00 }
        $pattern2 = { FF 75 08 6A 5B 8B EC E8 0C 0D 53 ?? ?? ?? ?? 89 9D F0 00 01 }

    condition:
        any of them
}