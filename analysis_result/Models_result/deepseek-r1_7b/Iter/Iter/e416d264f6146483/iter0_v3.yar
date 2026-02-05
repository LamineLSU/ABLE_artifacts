rule Bypass_Sample
{
    meta:
        description = "Evasion bypass rule (ExitProcess)"
        cape_options = "bp0=$pattern0+0,action0=skip,bp1=$pattern1+0,action1=skip,bp2=$pattern2+0,action2=skip,count=0"

    strings:
        $pattern0 = { 85 C0 0F 84 5E ?? 53 8B 45 }
        $pattern1 = { E8 8C 5D ?? 75 0C 83 C4 85 C0 0F 84 }
        $pattern2 = { 6A ?? 5A 8B CE E8 8D 4D 85 C0 }

    condition:
        any of them
}